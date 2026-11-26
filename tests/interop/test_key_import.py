import base64
import errno
import hashlib
import json
import os
import socket
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Literal
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request
from uuid import uuid4
from zipfile import ZipFile

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opentdf_sdk import AccessDenied, KasConfig, TdfError, create_tdf, open_tdf

if TYPE_CHECKING:
    import consumers
    import with_platform
else:
    from tests.interop import consumers, with_platform

PASSWORD = b"disposable-bundle-password"
ROOT_KEY = bytes(range(32))
REGISTRY = "policy.kasregistry.KeyAccessServerRegistryService"


def policy(
    endpoint: str, token: str, operation: str, body: dict[str, Any]
) -> dict[str, Any]:
    request = Request(
        f"{endpoint}/{REGISTRY}/{operation}",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
        },
    )
    with with_platform.HTTP.open(request, timeout=15) as response:
        result: dict[str, Any] = json.load(response)
        return result


def import_key(
    endpoint: str,
    token: str,
    kas_id: str,
    kid: str,
    encrypted_key: bytes,
    password: bytes,
    root_key: bytes,
) -> None:
    if len(encrypted_key) > 256 * 1024 or len(root_key) != 32:
        raise ValueError("Invalid key size")
    private = serialization.load_pem_private_key(encrypted_key, password=password)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
        private.curve, ec.SECP256R1
    ):
        raise ValueError("Expected a P-256 bundle key")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    nonce = os.urandom(12)
    wrapped = nonce + AESGCM(root_key).encrypt(nonce, private_pem, None)
    policy(
        endpoint,
        token,
        "CreateKey",
        {
            "kasId": kas_id,
            "keyId": kid,
            "keyAlgorithm": "ALGORITHM_EC_P256",
            "keyMode": "KEY_MODE_CONFIG_ROOT_KEY",
            "publicKeyCtx": {"pem": base64.b64encode(public_pem).decode()},
            "privateKeyCtx": {
                "keyId": "local-root",
                "wrappedKey": base64.b64encode(wrapped).decode(),
            },
        },
    )


def site_source(
    source: Path,
    destination: Path,
    *,
    kid: str | None = None,
    root_key: bytes | None = None,
) -> Path:
    for relative in (
        "opentdf-dev.yaml",
        "service/cmd/keycloak_data.yaml",
        "service/internal/fixtures/policy_fixtures.yaml",
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes((source / relative).read_bytes())
    path = destination / "opentdf-dev.yaml"
    config = path.read_text()
    if kid is not None:
        assert config.count("kid: e1\n") == 3
        config = config.replace("kid: e1\n", f"kid: {kid}\n")
    if root_key is not None:
        config = with_platform.checked_replace(
            config, "    key_management: false\n", "    key_management: true\n"
        )
        line = next(
            line
            for line in config.splitlines(keepends=True)
            if line.startswith("    root_key:")
        )
        config = with_platform.checked_replace(
            config, line, f"    root_key: {root_key.hex()}\n"
        )
    path.write_text(config)
    return destination


def ports(site: dict[str, str]) -> set[int]:
    kas_port = urlsplit(site["OTDF_KAS_URL"]).port
    idp_port = urlsplit(site["OTDF_TEST_IDP_URL"]).port
    assert kas_port is not None and idp_port is not None
    return {kas_port, idp_port, int(site["OTDF_TEST_DB_PORT"])}


def assert_offline(retired: set[int]) -> None:
    for port in retired:
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(("127.0.0.1", port)) == errno.ECONNREFUSED


@pytest.mark.e2e
def test_password_key_import_decrypts_with_producer_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TemporaryDirectory(prefix="bundle-key-import-", dir=tmp_path) as directory:
        work = Path(directory)
        sdk = Path(__file__).resolve().parents[2]
        rust_sdk = Path(
            os.environ.get("RUST_SDK", str(sdk.parent / "opentdf-rust-sdk"))
        )
        rust = consumers.rust_consumer(rust_sdk, work, release=False)
        source_path = os.environ.get("OTDF_TEST_PLATFORM_SOURCE")
        source = with_platform.platform_sources(
            Path(source_path) if source_path else None, work
        )
        binary_path = os.environ.get("OTDF_TEST_PLATFORM_BINARY")
        binary = with_platform.platform_binary(
            source, Path(binary_path) if binary_path else None, work
        )
        kid = str(uuid4())
        bundle_key = ec.generate_private_key(ec.SECP256R1())
        public_path = work / "bundle.pub.pem"
        public_path.write_bytes(
            bundle_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        private_pem = bundle_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        encrypted_key = subprocess.run(
            [
                "openssl",
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-v2prf",
                "hmacWithSHA256",
                "-iter",
                "600000",
                "-saltlen",
                "16",
                "-passout",
                "env:OTDF_TEST_KEY_PASSWORD",
            ],
            input=private_pem,
            env={**os.environ, "OTDF_TEST_KEY_PASSWORD": PASSWORD.decode()},
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        assert len(encrypted_key) <= 256 * 1024
        (work / "key.enc.pem").write_bytes(encrypted_key)
        plaintext = work / "payload.zip"
        with ZipFile(plaintext, "w") as payload:
            payload.writestr("workflow.yaml", "run:\n  activities: []\n")
            payload.writestr("files/secret.bin", bytes(range(256)) * 8193)
        expected = hashlib.sha256(plaintext.read_bytes()).digest()
        artifacts: list[tuple[Path, bytes]] = []

        with TemporaryDirectory(prefix="producer-", dir=work) as producer_directory:
            producer = Path(producer_directory)
            private_path = producer / "bundle.pem"
            private_path.touch(mode=0o600)
            private_path.write_bytes(private_pem)
            producer_source = site_source(source, producer / "source", kid=kid)
            with with_platform.platform_site(
                source=producer_source,
                binary=binary,
                work=producer / "site",
                ec_wrapping_key=private_path,
            ) as site_a:
                retired = ports(site_a)
                original_origin = site_a["OTDF_KAS_URL"]
                kas_a = KasConfig(
                    original_origin, site_a["OTDF_ACCESS_TOKEN"]
                ).with_key_algorithm("ec:secp256r1")
                profiles: tuple[Literal["java", "spec"], ...] = ("java", "spec")
                for profile in profiles:
                    archive = work / f"{profile}.tdf"
                    create_tdf(
                        plaintext,
                        archive,
                        kas=kas_a,
                        attribute=site_a["OTDF_ATTRIBUTE"],
                        key_id=kid,
                        profile=profile,
                    )
                    with ZipFile(archive) as zipped:
                        manifest_name = (
                            "0.manifest.json" if profile == "java" else "manifest.json"
                        )
                        grant = json.loads(zipped.read(manifest_name))[
                            "encryptionInformation"
                        ]["keyAccess"][0]
                        assert (grant["kid"], grant["url"]) == (kid, original_origin)
                    artifacts.append(
                        (archive, hashlib.sha256(archive.read_bytes()).digest())
                    )
                    archive = work / f"rust-{profile}.tdf"
                    subprocess.run(
                        rust
                        + [
                            "create-spec-p256" if profile == "spec" else "create-p256",
                            str(plaintext),
                            str(archive),
                        ],
                        env={
                            **os.environ,
                            **site_a,
                            "OTDF_TEST_AUTH_MODE": "public-key",
                            "OTDF_KAS_PUBLIC_KEY_FILE": str(public_path),
                            "OTDF_TEST_KAS_EC_KEY_ID": kid,
                            "OTDF_MANIFEST_KAS_URL": "",
                        },
                        check=True,
                        capture_output=True,
                    )
                    artifacts.append(
                        (archive, hashlib.sha256(archive.read_bytes()).digest())
                    )
        assert not private_path.exists()
        assert_offline(retired)
        print(
            "Producer KAS, IdP, database, and private-key workspace are offline",
            flush=True,
        )

        root_key = os.urandom(32)
        receiver_source = site_source(
            source, work / "receiver-source", root_key=root_key
        )
        with with_platform.platform_site(
            receiver_source, binary, work / "receiver", exclude_ports=retired
        ) as site_b:
            original_connect = socket.create_connection
            local_ports = ports(site_b)

            def local_connection(
                address: tuple[str, int], *args: Any, **kwargs: Any
            ) -> socket.socket:
                assert (
                    address[0] in {"localhost", "127.0.0.1", "::1"}
                    and address[1] in local_ports
                ), "Nonlocal endpoint contacted"
                return original_connect(address, *args, **kwargs)

            with monkeypatch.context() as connections:
                connections.setattr(socket, "create_connection", local_connection)
                endpoint = site_b["OTDF_KAS_URL"]
                token = site_b["OTDF_ACCESS_TOKEN"]
                admin = with_platform.fixture_token(
                    site_b["OTDF_TEST_IDP_URL"], "opentdf"
                )
                kas_id = policy(
                    endpoint,
                    admin,
                    "CreateKeyAccessServer",
                    {"uri": endpoint, "name": "local-bundle-kas"},
                )["keyAccessServer"]["id"]
                kas_b = (
                    KasConfig(endpoint, token)
                    .with_key_algorithm("ec:secp256r1")
                    .with_manifest_origin(original_origin)
                )
                output = work / "output.zip"
                with pytest.raises(TdfError, match="KAS Rewrap returned HTTP"):
                    open_tdf(artifacts[0][0], output, kas=kas_b)
                assert not output.exists()
                with pytest.raises(ValueError):
                    import_key(
                        endpoint,
                        admin,
                        kas_id,
                        kid,
                        encrypted_key,
                        b"wrong-password",
                        root_key,
                    )
                with pytest.raises(HTTPError) as forbidden:
                    import_key(
                        endpoint, token, kas_id, kid, encrypted_key, PASSWORD, root_key
                    )
                assert forbidden.value.code == 403
                import_key(
                    endpoint, admin, kas_id, kid, encrypted_key, PASSWORD, root_key
                )
                record = policy(
                    endpoint, admin, "GetKey", {"key": {"uri": endpoint, "kid": kid}}
                )["kasKey"]["key"]
                assert record["keyMode"] == "KEY_MODE_CONFIG_ROOT_KEY"
                assert record["keyId"] == kid

                for archive, digest in artifacts:
                    open_tdf(archive, output, kas=kas_b)
                    assert hashlib.sha256(output.read_bytes()).digest() == expected
                    assert hashlib.sha256(archive.read_bytes()).digest() == digest
                    output.unlink()
                    subprocess.run(
                        rust + ["open-p256", str(archive), str(output)],
                        env={
                            **os.environ,
                            **site_b,
                            "OTDF_TEST_AUTH_MODE": "bearer",
                            "OTDF_MANIFEST_KAS_URL": original_origin,
                        },
                        check=True,
                        capture_output=True,
                    )
                    assert hashlib.sha256(output.read_bytes()).digest() == expected
                    assert hashlib.sha256(archive.read_bytes()).digest() == digest
                    output.unlink()
                denied = (
                    KasConfig(endpoint, site_b["OTDF_DENIED_ACCESS_TOKEN"])
                    .with_key_algorithm("ec:secp256r1")
                    .with_manifest_origin(original_origin)
                )
                with pytest.raises(AccessDenied):
                    open_tdf(artifacts[0][0], output, kas=denied)
                producer_token = (
                    KasConfig(endpoint, site_a["OTDF_ACCESS_TOKEN"])
                    .with_key_algorithm("ec:secp256r1")
                    .with_manifest_origin(original_origin)
                )
                with pytest.raises(TdfError, match="HTTP 401"):
                    open_tdf(artifacts[0][0], output, kas=producer_token)
                with pytest.raises(TdfError, match="Untrusted manifest KAS origin"):
                    open_tdf(
                        artifacts[0][0],
                        output,
                        kas=kas_b.with_manifest_origin("https://wrong.example.invalid"),
                    )
                assert not output.exists()
                assert not list(work.glob(".tdf-*"))
                logs = (work / "receiver" / "platform.log").read_bytes()
                assert PASSWORD not in logs
                assert root_key.hex().encode() not in logs
                assert b"-----BEGIN PRIVATE KEY-----" not in logs
                print(
                    "Native registry import and both SDKs/TDF profiles "
                    "decrypted locally; "
                    "denial controls passed",
                    flush=True,
                )
            assert_offline(retired)
        assert_offline(local_ports | retired)
    assert not work.exists()


def test_key_import_uses_native_registry_and_receiver_root_key() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSWORD),
    )
    with patch(f"{__name__}.policy") as request:
        import_key(
            "http://localhost:8080",
            "admin",
            "kas-id",
            "bundle-id",
            encrypted,
            PASSWORD,
            ROOT_KEY,
        )
    request.assert_called_once()
    endpoint, token, operation, body = request.call_args.args
    assert (endpoint, token, operation) == (
        "http://localhost:8080",
        "admin",
        "CreateKey",
    )
    assert body["kasId"] == "kas-id"
    assert body["keyId"] == "bundle-id"
    assert body["keyAlgorithm"] == "ALGORITHM_EC_P256"
    assert body["keyMode"] == "KEY_MODE_CONFIG_ROOT_KEY"
    assert body["privateKeyCtx"]["keyId"] == "local-root"
    assert PASSWORD not in json.dumps(body).encode()
    assert b"-----BEGIN PRIVATE KEY-----" not in json.dumps(body).encode()
    wrapped = base64.b64decode(body["privateKeyCtx"]["wrappedKey"], validate=True)
    plaintext = AESGCM(ROOT_KEY).decrypt(wrapped[:12], wrapped[12:], None)
    imported = serialization.load_pem_private_key(plaintext, password=None)
    assert isinstance(imported, ec.EllipticCurvePrivateKey)
    assert imported.private_numbers() == key.private_numbers()
    assert base64.b64decode(
        body["publicKeyCtx"]["pem"], validate=True
    ) == key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert PASSWORD not in plaintext
    assert plaintext not in wrapped
    with pytest.raises(InvalidTag):
        AESGCM(b"x" * 32).decrypt(wrapped[:12], wrapped[12:], None)


@pytest.mark.parametrize(
    "invalid", ["password", "plaintext", "rsa", "p384", "oversize", "root"]
)
def test_invalid_key_import_does_not_contact_kas(invalid: str) -> None:
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if invalid == "rsa"
        else ec.generate_private_key(
            ec.SECP384R1() if invalid == "p384" else ec.SECP256R1()
        )
    )
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
        if invalid == "plaintext"
        else serialization.BestAvailableEncryption(PASSWORD),
    )
    if invalid == "oversize":
        encrypted += b" " * (256 * 1024)
    with (
        patch(f"{__name__}.policy") as request,
        pytest.raises((ValueError, TypeError)),
    ):
        import_key(
            "http://localhost:8080",
            "admin",
            "kas-id",
            "bundle-id",
            encrypted,
            b"wrong" if invalid == "password" else PASSWORD,
            ROOT_KEY[:16] if invalid == "root" else ROOT_KEY,
        )
    request.assert_not_called()
