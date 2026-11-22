import base64
import http.client
import json
import time
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class TdfError(ValueError):
    """A TDF could not be created or opened."""


class AccessDenied(TdfError):
    """KAS denied access to the TDF."""


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(value: Any, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise TdfError("Expected a base64 string")
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise TdfError("Invalid base64") from exc
    if length is not None and len(data) != length:
        raise TdfError("Unexpected decoded length")
    return data


def utf8_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _jwt_part(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _oaep() -> padding.OAEP:
    # The Java compatibility profile uses OAEP with SHA-1 for both digests.
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None
    )


class Kas:
    def __init__(self, url: str, token: str) -> None:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise TdfError("Invalid KAS origin") from exc
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.scheme not in {"https", "http"}
        ):
            raise TdfError("KAS URL must be an HTTP(S) origin")
        if parsed.scheme == "http" and parsed.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise TdfError("KAS HTTP is limited to loopback")
        if (
            not token
            or not token.isascii()
            or any(not 0x21 <= ord(c) <= 0x7E for c in token)
        ):
            raise TdfError(
                "Access token must contain printable ASCII without whitespace"
            )
        self.url = url.rstrip("/")
        self.host = parsed.hostname
        self.port = port
        self.https = parsed.scheme == "https"
        self.token = token

    def _post(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        connection_class = (
            http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        )
        connection = connection_class(self.host, self.port, timeout=10)
        try:
            connection.request(
                "POST",
                f"/kas.AccessService/{method}",
                utf8_json(body),
                {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Connect-Protocol-Version": "1",
                },
            )
            with connection.getresponse() as response:
                status = response.status
                payload = response.read(128 * 1024 + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise TdfError(f"KAS {method} could not be reached") from exc
        finally:
            connection.close()
        if len(payload) > 128 * 1024:
            raise TdfError("KAS response exceeded the size limit")
        try:
            result = json.loads(payload)
        except (ValueError, RecursionError) as exc:
            raise TdfError(f"KAS {method} returned HTTP {status}") from exc
        if not isinstance(result, dict):
            raise TdfError("Invalid KAS response")
        if status == 403 and result.get("code") == "permission_denied":
            raise AccessDenied("KAS denied access")
        if status != 200:
            raise TdfError(f"KAS {method} returned HTTP {status}")
        return result

    def wrap(self, key: bytes, key_id: str | None) -> tuple[str, str]:
        request = {"algorithm": "rsa:2048"}
        if key_id is not None:
            request["kid"] = key_id
        response = self._post("PublicKey", request)
        kid, pem = response.get("kid"), response.get("publicKey")
        if not isinstance(kid, str) or not kid or not isinstance(pem, str):
            raise TdfError("KAS did not return a key ID and public key")
        if key_id is not None and kid != key_id:
            raise TdfError("KAS returned a different key ID")
        try:
            public_key = serialization.load_pem_public_key(pem.encode())
        except ValueError as exc:
            raise TdfError("Invalid KAS public key") from exc
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
            raise TdfError("KAS public key must be RSA-2048")
        return kid, encode(public_key.encrypt(key, _oaep()))

    def unwrap(self, policy: str, key_access: dict[str, Any]) -> bytes:
        session = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = session.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        request = {
            "policy": policy,
            "clientPublicKey": public_pem.decode("ascii"),
            "keyAccess": key_access,
        }
        now = int(time.time())
        claims = {
            "requestBody": utf8_json(request).decode(),
            "iat": now,
            "exp": now + 60,
        }
        signing_input = (
            _jwt_part(b'{"alg":"RS256"}') + b"." + _jwt_part(utf8_json(claims))
        )
        signature = session.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        response = self._post(
            "Rewrap",
            {
                "signedRequestToken": (
                    signing_input + b"." + _jwt_part(signature)
                ).decode()
            },
        )
        encrypted_key = decode(response.get("entityWrappedKey"), 256)
        try:
            key = session.decrypt(encrypted_key, _oaep())
        except ValueError as exc:
            raise TdfError("Invalid session-wrapped key") from exc
        if len(key) != 32:
            raise TdfError("Expected a 256-bit data key")
        return key
