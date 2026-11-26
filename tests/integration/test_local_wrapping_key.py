import base64
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from opentdf_sdk import KasConfig, TdfError, create_tdf


def test_create_with_explicit_bundle_public_key_needs_no_producer_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    public = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    config = KasConfig.from_public_key("https://producer.invalid", "bundle-key", public)
    monkeypatch.setattr(
        KasConfig, "_post", lambda *args: pytest.fail("Producer contacted")
    )
    source, destination = tmp_path / "source", tmp_path / "payload.tdf"
    source.write_bytes(b"private bundle contents")
    create_tdf(
        source,
        destination,
        kas=config,
        attribute="https://example.com/attr/environment/value/test",
        key_id="bundle-key",
    )
    with ZipFile(destination) as archive:
        manifest = json.loads(archive.read("0.manifest.json"))
        entry = manifest["encryptionInformation"]["keyAccess"][0]
        assert entry["url"] == "https://producer.invalid"
        assert entry["kid"] == "bundle-key"
        assert entry["type"] == "ec-wrapped"
        ephemeral = serialization.load_pem_public_key(
            entry["ephemeralPublicKey"].encode()
        )
        assert isinstance(ephemeral, ec.EllipticCurvePublicKey)
        wrapping = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(b"TDF").digest(),
            info=b"",
        ).derive(private.exchange(ec.ECDH(), ephemeral))
        wrapped = base64.b64decode(entry["wrappedKey"])
        data_key = AESGCM(wrapping).decrypt(wrapped[:12], wrapped[12:], None)
        payload = archive.read("0.payload")
        assert (
            AESGCM(data_key).decrypt(payload[:12], payload[12:], None)
            == source.read_bytes()
        )
    with pytest.raises(TdfError, match="key ID"):
        config.wrap(bytes(32), "different-key")


@pytest.mark.parametrize("kind", ["empty_id", "malformed", "p384", "private"])
def test_explicit_wrapping_key_rejects_invalid_material(kind: str) -> None:
    key = ec.generate_private_key(ec.SECP384R1() if kind == "p384" else ec.SECP256R1())
    public = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    if kind == "private":
        public = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    elif kind == "malformed":
        public = "invalid"
    with pytest.raises(TdfError):
        KasConfig.from_public_key(
            "https://producer.invalid", "" if kind == "empty_id" else "key", public
        )
