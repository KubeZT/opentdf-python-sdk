import base64
import http.client
import json
from pathlib import Path
from typing import Literal
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from opentdf_sdk import TdfError, create_tdf, open_tdf

_ENDPOINT = "http://LOCALHOST:18880"
_MANIFEST_ORIGIN = "https://Publisher.Example:8443"
_TOKEN = "local-route-test-token"
_ATTRIBUTE = "https://example.com/attr/department/value/engineering"


@pytest.mark.parametrize("profile", ["java", "spec"])
def test_trusted_origin_uses_only_configured_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: Literal["java", "spec"]
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    oaep = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
    response = Mock(status=200)
    connection = Mock(spec=http.client.HTTPConnection)
    connection.getresponse.return_value.__enter__ = Mock(return_value=response)
    connection.getresponse.return_value.__exit__ = Mock(return_value=False)
    configured_endpoint = Mock(return_value=connection)
    unexpected_endpoint = Mock(side_effect=AssertionError("Unexpected KAS connection"))
    monkeypatch.setattr(http.client, "HTTPConnection", configured_endpoint)
    monkeypatch.setattr(http.client, "HTTPSConnection", unexpected_endpoint)

    def request(method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
        assert method == "POST"
        assert headers["Authorization"] == f"Bearer {_TOKEN}"
        message = json.loads(body)
        if path == "/kas.AccessService/PublicKey":
            assert message == {"algorithm": "rsa:2048"}
            result = {"kid": "local-key", "publicKey": public_pem.decode("ascii")}
        else:
            assert path == "/kas.AccessService/Rewrap"
            _, claims, _ = message["signedRequestToken"].split(".")
            claims = json.loads(
                base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))
            )
            rewrap_request = json.loads(claims["requestBody"])
            key_access = rewrap_request["keyAccess"]
            assert key_access["url"] == _MANIFEST_ORIGIN
            assert key_access["kid"] == "local-key"
            key = private_key.decrypt(base64.b64decode(key_access["wrappedKey"]), oaep)
            client_key = serialization.load_pem_public_key(
                rewrap_request["clientPublicKey"].encode("ascii")
            )
            assert isinstance(client_key, rsa.RSAPublicKey)
            result = {
                "entityWrappedKey": base64.b64encode(
                    client_key.encrypt(key, oaep)
                ).decode("ascii")
            }
        response.read.return_value = json.dumps(result).encode()

    connection.request.side_effect = request
    source = tmp_path / "input.bin"
    source.write_bytes(b"aliased KAS route")
    archive = tmp_path / "archive.tdf"
    restored = tmp_path / "restored.bin"
    create_tdf(
        source,
        archive,
        kas_url=_ENDPOINT,
        access_token=_TOKEN,
        attribute=_ATTRIBUTE,
        profile=profile,
        manifest_kas_url=f"{_MANIFEST_ORIGIN}/",
    )
    manifest_name = "manifest.json" if profile == "spec" else "0.manifest.json"
    with ZipFile(archive) as container:
        manifest_bytes = container.read(manifest_name)
    access = json.loads(manifest_bytes)["encryptionInformation"]["keyAccess"]
    assert [entry["url"] for entry in access] == [_MANIFEST_ORIGIN]
    assert _TOKEN.encode("ascii") not in manifest_bytes
    assert _ENDPOINT.encode("ascii") not in manifest_bytes

    archive_bytes = archive.read_bytes()
    for untrusted in (None, _MANIFEST_ORIGIN.lower()):
        with pytest.raises(TdfError, match="Untrusted manifest KAS origin"):
            open_tdf(
                archive,
                restored,
                kas_url=_ENDPOINT,
                access_token=_TOKEN,
                manifest_kas_url=untrusted,
            )
        configured_endpoint.assert_called_once_with("localhost", 18880, timeout=10)
        assert not restored.exists()
        assert not list(tmp_path.glob(".tdf-*"))
        assert archive.read_bytes() == archive_bytes

    open_tdf(
        archive,
        restored,
        kas_url=_ENDPOINT,
        access_token=_TOKEN,
        manifest_kas_url=f"{_MANIFEST_ORIGIN}/",
    )
    assert restored.read_bytes() == source.read_bytes()
    assert archive.read_bytes() == archive_bytes
    assert configured_endpoint.call_count == 2
    configured_endpoint.assert_called_with("localhost", 18880, timeout=10)
    unexpected_endpoint.assert_not_called()


@pytest.mark.parametrize(
    "origin",
    [
        "http://publisher.example",
        "https://publisher.example//",
        "https://publisher.example/path",
        "https://publisher.example?",
        "https://publisher.example#",
        "https://someone@publisher.example",
        "https://publisher.example:",
        "https://publisher.example:65536",
        "http://prefix[::1]",
        "http://[::1]suffix",
        " https://publisher.example",
        "https://publi\nsher.example",
    ],
)
def test_invalid_manifest_origin_fails_before_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin: str
) -> None:
    unexpected = Mock(side_effect=AssertionError("Unexpected KAS connection"))
    monkeypatch.setattr(http.client, "HTTPConnection", unexpected)
    monkeypatch.setattr(http.client, "HTTPSConnection", unexpected)
    source = tmp_path / "input.bin"
    source.write_bytes(b"invalid route")
    destination = tmp_path / "archive.tdf"
    with pytest.raises(TdfError, match="KAS"):
        create_tdf(
            source,
            destination,
            kas_url=_ENDPOINT,
            access_token=_TOKEN,
            attribute=_ATTRIBUTE,
            manifest_kas_url=origin,
        )
    unexpected.assert_not_called()
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == [source]
