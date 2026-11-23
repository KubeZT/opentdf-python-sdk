import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import SplitResult
from zipfile import ZipFile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from opentdf_sdk import KasConfig, TdfError, _kas, _kas_auth, create_tdf, open_tdf

_PLATFORM = "http://localhost:8100"
_KAS = "http://localhost:8101"
_ISSUER = "http://localhost:8102/realms/test"
_ATTRIBUTE = "https://example.com/attr/department/value/engineering"


def _pem(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _box(
    private: ec.EllipticCurvePrivateKey, public: ec.EllipticCurvePublicKey
) -> AESGCM:
    secret = private.exchange(ec.ECDH(), public)
    return AESGCM(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(b"TDF").digest(),
            info=b"",
        ).derive(secret)
    )


def _decode_url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_empty_wrapping_key_id_rejected_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_request(*args: object) -> None:
        pytest.fail("Invalid wrapping key ID reached KAS")

    monkeypatch.setattr(KasConfig, "_post", unexpected_request)
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    destination = tmp_path / "archive.tdf"
    with pytest.raises(TdfError, match="Invalid KAS key ID"):
        create_tdf(
            source,
            destination,
            kas=KasConfig(_KAS, "test"),
            attribute=_ATTRIBUTE,
            key_id="",
        )
    assert not destination.exists()
    assert not any(tmp_path.glob(".tdf-*"))


@pytest.mark.parametrize("profile", ["java", "spec"])
def test_p256_key_access_for_ec_and_rsa_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: Literal["java", "spec"],
) -> None:
    generate_key = ec.generate_private_key
    private = generate_key(ec.SECP256R1())
    sessions: list[str] = []
    generated: list[ec.EllipticCurvePrivateKey] = []

    def track_key(curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
        key = generate_key(curve)
        generated.append(key)
        return key

    monkeypatch.setattr(ec, "generate_private_key", track_key)

    def kas_request(
        config: KasConfig, method: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        if method == "PublicKey":
            assert request == {"algorithm": "ec:secp256r1", "kid": "e1"}
            return {"kid": "e1", "publicKey": _pem(private.public_key())}
        assert method == "Rewrap"
        header, claims, signature = request["signedRequestToken"].split(".")
        algorithm = json.loads(_decode_url(header))["alg"]
        request_body = json.loads(json.loads(_decode_url(claims))["requestBody"])
        entry = request_body["keyAccess"]
        assert entry["kid"] == "e1"
        assert entry["type"] == "ec-wrapped"
        assert entry["url"] == _KAS
        encrypted = base64.b64decode(entry["wrappedKey"])
        ephemeral = serialization.load_pem_public_key(
            entry["ephemeralPublicKey"].encode()
        )
        assert isinstance(ephemeral, ec.EllipticCurvePublicKey)
        assert isinstance(ephemeral.curve, ec.SECP256R1)
        key = _box(private, ephemeral).decrypt(encrypted[:12], encrypted[12:], None)
        assert len(key) == 32
        client = serialization.load_pem_public_key(
            request_body["clientPublicKey"].encode()
        )
        signed = f"{header}.{claims}".encode()
        actual_signature = _decode_url(signature)
        sessions.append(algorithm)
        if algorithm == "ES256":
            assert isinstance(client, ec.EllipticCurvePublicKey)
            assert isinstance(client.curve, ec.SECP256R1)
            assert len(actual_signature) == 64
            der = encode_dss_signature(
                int.from_bytes(actual_signature[:32], "big"),
                int.from_bytes(actual_signature[32:], "big"),
            )
            assert (
                client.public_numbers() == generated[-2].public_key().public_numbers()
            )
            signer = generated[-1].public_key()
            assert client.public_numbers() != signer.public_numbers()
            signer.verify(der, signed, ec.ECDSA(hashes.SHA256()))
            response_private = generate_key(ec.SECP256R1())
            nonce = bytes(12)
            response_key = nonce + _box(response_private, client).encrypt(
                nonce, key, None
            )
            return {
                "sessionPublicKey": _pem(response_private.public_key()),
                "entityWrappedKey": base64.b64encode(response_key).decode(),
            }
        assert algorithm == "RS256"
        assert isinstance(client, rsa.RSAPublicKey)
        client.verify(actual_signature, signed, padding.PKCS1v15(), hashes.SHA256())
        response_key = client.encrypt(
            key, padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
        )
        return {"entityWrappedKey": base64.b64encode(response_key).decode()}

    monkeypatch.setattr(KasConfig, "_post", kas_request)
    source = tmp_path / "input"
    source.write_bytes(b"sample plaintext")
    archive = tmp_path / "sample.tdf"
    direct = KasConfig(_KAS, "test")
    p256 = direct.with_key_algorithm("ec:secp256r1")
    create_tdf(
        source, archive, kas=p256, attribute=_ATTRIBUTE, key_id="e1", profile=profile
    )
    for config in (p256, direct):
        destination = tmp_path / f"recovered-{len(sessions)}"
        open_tdf(archive, destination, kas=config)
        assert destination.read_bytes() == source.read_bytes()
    assert sessions == ["ES256", "RS256"]

    name = "manifest.json" if profile == "spec" else "0.manifest.json"
    with ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read(name))
        payload = bundle.read("0.payload")
    manifest["encryptionInformation"]["keyAccess"][0]["ephemeralPublicKey"] = _pem(
        ec.generate_private_key(ec.SECP384R1()).public_key()
    )
    invalid = tmp_path / "invalid.tdf"
    with ZipFile(invalid, "w") as bundle:
        bundle.writestr("0.payload", payload)
        bundle.writestr(name, json.dumps(manifest))
    with pytest.raises(TdfError, match="P-256 public key"):
        open_tdf(invalid, tmp_path / "invalid-output", kas=p256)
    assert sessions == ["ES256", "RS256"]
    assert not (tmp_path / "invalid-output").exists()


def test_discovery_client_credentials_and_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    calls: list[str] = []
    counter = 0
    now = 100.0

    def response(
        endpoint: SplitResult,
        method: str,
        path: str,
        context: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        nonlocal counter
        calls.append(path)
        if path == "/.well-known/opentdf-configuration":
            assert endpoint.port == 8100 and method == "GET" and not headers
            return 200, {"base_key": {"kas_uri": _KAS}, "platform_issuer": _ISSUER}
        if path == "/realms/test/.well-known/openid-configuration":
            assert endpoint.port == 8102 and method == "GET" and not headers
            return 200, {
                "issuer": _ISSUER,
                "token_endpoint": f"{_ISSUER}/token?fixed=1",
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            }
        if path == "/realms/test/token?fixed=1":
            assert endpoint.port == 8102 and method == "POST"
            expected = base64.b64encode(b"id%3A+name:s%3A%2B%26").decode()
            assert headers == {
                "Authorization": f"Basic {expected}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            assert body == b"grant_type=client_credentials"
            counter += 1
            return 200, {
                "token_type": "Bearer",
                "access_token": f"token-{counter}",
                "expires_in": 100,
            }
        assert endpoint.port == 8101 and method == "POST"
        assert path == "/kas.AccessService/PublicKey"
        assert headers and headers["Authorization"] == f"Bearer token-{counter}"
        return 200, {"kid": "r1", "publicKey": _pem(private.public_key())}

    monkeypatch.setattr(_kas_auth, "request_json", response)
    monkeypatch.setattr(_kas, "request_json", response)
    monkeypatch.setattr(_kas_auth, "monotonic", lambda: now)
    config = KasConfig.discover_with_client_credentials(
        _PLATFORM, _ISSUER, "id: name", "s:+&"
    )
    assert config.manifest_url == _KAS
    assert calls == ["/.well-known/opentdf-configuration"]
    config.wrap(bytes(32), None)
    assert counter == 1
    now += 89
    config.with_manifest_origin("https://producer.invalid").wrap(bytes(32), None)
    assert counter == 1
    now += 1
    config.wrap(bytes(32), None)
    assert counter == 2
    assert calls.count("/realms/test/.well-known/openid-configuration") == 1


@pytest.mark.parametrize(
    ("well_known", "error"),
    [
        ({"platform_issuer": "https://untrusted.invalid"}, "Platform issuer"),
        ({"platform_issuer": _ISSUER, "base_key": 7}, "advertised base key"),
        (
            {
                "platform_issuer": _ISSUER,
                "base_key": {"kas_uri": _KAS, "kasUri": _KAS},
            },
            "advertised KAS origin",
        ),
        (
            {"platform_issuer": _ISSUER, "base_key": {"public_key": {}}},
            "advertised KAS origin",
        ),
        (
            {"platform_issuer": _ISSUER, "base_key": {"kas_uri": f"{_KAS}/redirect"}},
            "Invalid KAS origin",
        ),
    ],
)
def test_discovery_rejects_untrusted_configuration_without_credentials(
    monkeypatch: pytest.MonkeyPatch, well_known: dict[str, Any], error: str
) -> None:
    def response(
        endpoint: SplitResult, method: str, path: str, context: str
    ) -> tuple[int, dict[str, Any]]:
        assert endpoint.port == 8100
        assert method == "GET" and path == "/.well-known/opentdf-configuration"
        return 200, well_known

    monkeypatch.setattr(_kas_auth, "request_json", response)
    with pytest.raises(TdfError, match=error):
        KasConfig.discover_with_client_credentials(_PLATFORM, _ISSUER, "id", "secret")


@pytest.mark.parametrize("status", [200, 307])
def test_oidc_never_sends_secret_to_advertised_other_origin(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    def response(
        endpoint: SplitResult, method: str, path: str, context: str
    ) -> tuple[int, dict[str, Any]]:
        assert endpoint.port == 8102 and method == "GET"
        assert path == "/realms/test/.well-known/openid-configuration"
        return status, {"issuer": _ISSUER, "token_endpoint": f"{_KAS}/token"}

    monkeypatch.setattr(_kas_auth, "request_json", response)
    config = KasConfig.from_client_credentials(_KAS, _ISSUER, "id", "secret")
    with pytest.raises(TdfError, match="issuer origin|HTTP 307"):
        config.wrap(bytes(32), None)


@pytest.mark.parametrize("configuration", [{}, {"base_key": None}, {"base_key": {}}])
def test_discovery_uses_cohosted_kas_when_no_base_key(
    monkeypatch: pytest.MonkeyPatch, configuration: dict[str, Any]
) -> None:
    def response(
        endpoint: SplitResult, method: str, path: str, context: str
    ) -> tuple[int, dict[str, Any]]:
        assert endpoint.port == 8100
        assert method == "GET" and path == "/.well-known/opentdf-configuration"
        return 200, configuration

    monkeypatch.setattr(_kas_auth, "request_json", response)
    config = KasConfig.discover(f"{_PLATFORM}/", "test")
    assert config.manifest_url == _PLATFORM
