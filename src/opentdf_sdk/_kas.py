import base64
import hashlib
import json
import os
import time
from copy import copy
from typing import Any, Literal

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._errors import AccessDenied as AccessDenied
from ._errors import TdfError as TdfError
from ._kas_auth import (
    ClientCredentials,
    bearer_token,
    discover_platform,
    request_json,
    split_url,
)

KasAlgorithm = Literal["rsa:2048", "ec:secp256r1"]
_P256: Literal["ec:secp256r1"] = "ec:secp256r1"
_EC_BOX_LENGTH = 12 + 32 + 16
_TDF_SALT = hashlib.sha256(b"TDF").digest()


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


def _public_key(pem: object) -> object:
    if not isinstance(pem, str) or not pem.isascii():
        raise TdfError("Expected a PEM public key")
    try:
        return serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm):
        raise TdfError("Invalid PEM public key") from None


def _p256_public(pem: object) -> ec.EllipticCurvePublicKey:
    key = _public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise TdfError("Expected a P-256 public key")
    return key


def _public_pem(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _ec_box(
    private: ec.EllipticCurvePrivateKey, public: ec.EllipticCurvePublicKey
) -> AESGCM:
    secret = private.exchange(ec.ECDH(), public)
    return AESGCM(
        HKDF(algorithm=hashes.SHA256(), length=32, salt=_TDF_SALT, info=b"").derive(
            secret
        )
    )


def validate_wrapped_key(entry: dict[str, Any]) -> None:
    ephemeral = entry.get("ephemeralPublicKey", "")
    if entry.get("type") == "ec-wrapped":
        _p256_public(ephemeral)
        decode(entry.get("wrappedKey"), _EC_BOX_LENGTH)
    else:
        if ephemeral != "":
            raise TdfError("Unexpected ephemeral public key for RSA-wrapped key")
        decode(entry.get("wrappedKey"), 256)


class KasConfig:
    """A trusted KAS endpoint, its credential source, and its key algorithm."""

    def __init__(
        self, url: str, token: str, *, manifest_kas_url: str | None = None
    ) -> None:
        self._configure(url, bearer_token(token), manifest_kas_url)

    def _configure(
        self,
        url: str,
        source: str | ClientCredentials | None,
        manifest_kas_url: str | None,
    ) -> None:
        self._endpoint = split_url(url, purpose="KAS origin")
        if manifest_kas_url is not None:
            split_url(manifest_kas_url, purpose="KAS origin")
        self._manifest_url = (
            url if manifest_kas_url is None else manifest_kas_url
        ).removesuffix("/")
        self._source = source
        self._algorithm: KasAlgorithm = "rsa:2048"
        self._wrapping_key: tuple[str, str] | None = None

    @classmethod
    def from_public_key(cls, origin: str, key_id: str, public_key: str) -> "KasConfig":
        """Encrypt with an explicit P-256 wrapping key without contacting its KAS."""
        if not isinstance(key_id, str) or not key_id:
            raise TdfError("Invalid KAS key ID")
        _p256_public(public_key)
        config = cls.__new__(cls)
        config._configure(origin, None, None)
        config._algorithm = _P256
        config._wrapping_key = key_id, public_key
        return config

    @classmethod
    def from_client_credentials(
        cls, endpoint: str, issuer: str, client_id: str, client_secret: str
    ) -> "KasConfig":
        """Use OAuth client credentials obtained from an explicitly trusted issuer."""
        config = cls.__new__(cls)
        config._configure(
            endpoint, ClientCredentials(issuer, client_id, client_secret), None
        )
        return config

    @classmethod
    def discover(cls, platform: str, access_token: str) -> "KasConfig":
        """Use the KAS advertised by a trusted OpenTDF platform."""
        endpoint, _ = discover_platform(platform)
        return cls(endpoint, access_token)

    @classmethod
    def discover_with_client_credentials(
        cls, platform: str, issuer: str, client_id: str, client_secret: str
    ) -> "KasConfig":
        """Discover a KAS and check the advertised issuer before using credentials."""
        endpoint, advertised_issuer = discover_platform(platform)
        if advertised_issuer != issuer:
            raise TdfError("Platform issuer does not match the configured issuer")
        if (
            split_url(platform).scheme == "https"
            and split_url(issuer, allow_path=True).scheme != "https"
        ):
            raise TdfError("HTTPS platform advertised a plaintext issuer")
        return cls.from_client_credentials(endpoint, issuer, client_id, client_secret)

    def with_key_algorithm(self, algorithm: KasAlgorithm) -> "KasConfig":
        """Return a configuration with the selected wrapping and session key type."""
        if algorithm not in ("rsa:2048", _P256):
            raise TdfError("Unsupported KAS key algorithm")
        result = copy(self)
        result._algorithm = algorithm
        return result

    def with_manifest_origin(self, origin: str) -> "KasConfig":
        """Return a configuration for archives that name a specific KAS origin."""
        split_url(origin, purpose="KAS origin")
        result = copy(self)
        result._manifest_url = origin.removesuffix("/")
        return result

    @property
    def manifest_url(self) -> str:
        return self._manifest_url

    def _post(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        if self._source is None:
            raise TdfError("KAS credentials are required for this operation")
        token = self._source if isinstance(self._source, str) else self._source.token()
        status, result = request_json(
            self._endpoint,
            "POST",
            f"/kas.AccessService/{method}",
            f"KAS {method}",
            body=utf8_json(body),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Connect-Protocol-Version": "1",
            },
        )
        if status == 403 and result.get("code") == "permission_denied":
            raise AccessDenied("KAS denied access")
        if status != 200:
            raise TdfError(f"KAS {method} returned HTTP {status}")
        return result

    def wrap(
        self, key: bytes, key_id: str | None
    ) -> tuple[str, str] | tuple[str, str, str]:
        request: dict[str, str] = {"algorithm": self._algorithm}
        if key_id is not None:
            if not isinstance(key_id, str) or not key_id:
                raise TdfError("Invalid KAS key ID")
            request["kid"] = key_id
        if self._wrapping_key is None:
            response = self._post("PublicKey", request)
            kid, pem = response.get("kid"), response.get("publicKey")
        else:
            kid, pem = self._wrapping_key
        if not isinstance(kid, str) or not kid or not isinstance(pem, str):
            raise TdfError("KAS did not return a key ID and public key")
        if key_id is not None and kid != key_id:
            raise TdfError("KAS returned a different key ID")
        if self._algorithm == _P256:
            ephemeral = ec.generate_private_key(ec.SECP256R1())
            nonce = os.urandom(12)
            box = _ec_box(ephemeral, _p256_public(pem))
            return (
                kid,
                encode(nonce + box.encrypt(nonce, key, None)),
                _public_pem(ephemeral.public_key()),
            )
        public_key = _public_key(pem)
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
            raise TdfError("KAS public key must be RSA-2048")
        return kid, encode(public_key.encrypt(key, _oaep()))

    def unwrap(self, policy: str, key_access: dict[str, Any]) -> bytes:
        use_ec = self._algorithm == _P256
        session = (
            ec.generate_private_key(ec.SECP256R1())
            if use_ec
            else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )
        request = {
            "policy": policy,
            "clientPublicKey": _public_pem(session.public_key()),
            "keyAccess": key_access,
        }
        now = int(time.time())
        claims = {
            "requestBody": utf8_json(request).decode(),
            "iat": now,
            "exp": now + 60,
        }
        header = b'{"alg":"ES256"}' if use_ec else b'{"alg":"RS256"}'
        signing_input = _jwt_part(header) + b"." + _jwt_part(utf8_json(claims))
        if isinstance(session, ec.EllipticCurvePrivateKey):
            signer = ec.generate_private_key(ec.SECP256R1())
            r, s = decode_dss_signature(
                signer.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            )
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            signature = session.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        response = self._post(
            "Rewrap",
            {
                "signedRequestToken": (
                    signing_input + b"." + _jwt_part(signature)
                ).decode(),
            },
        )
        try:
            if isinstance(session, ec.EllipticCurvePrivateKey):
                encrypted = decode(response.get("entityWrappedKey"), _EC_BOX_LENGTH)
                box = _ec_box(session, _p256_public(response.get("sessionPublicKey")))
                key = box.decrypt(encrypted[:12], encrypted[12:], None)
            else:
                encrypted = decode(response.get("entityWrappedKey"), 256)
                key = session.decrypt(encrypted, _oaep())
        except (ValueError, InvalidTag) as exc:
            raise TdfError("Invalid session-wrapped key") from exc
        if len(key) != 32:
            raise TdfError("Expected a 256-bit data key")
        return key


Kas = KasConfig
