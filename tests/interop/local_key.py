from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from zipfile import ZipFile

from consumers import packaged_commands
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from matrix import sdk_roots

ORIGIN = "https://producer.invalid"
ATTRIBUTE = "https://example.com/attr/environment/value/test"
KEY_ID = "77170d7a-0af3-4309-9a0f-f4ac862183d1"


def box(private: ec.EllipticCurvePrivateKey, public: str) -> AESGCM:
    peer = serialization.load_pem_public_key(public.encode())
    assert isinstance(peer, ec.EllipticCurvePublicKey)
    secret = private.exchange(ec.ECDH(), peer)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(b"TDF").digest(),
        info=b"",
    ).derive(secret)
    return AESGCM(key)


def main() -> None:
    root, python_sdk = sdk_roots("Test packaged SDK per-bundle wrapping keys.")
    private = ec.generate_private_key(ec.SECP256R1())
    public = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    calls: list[str] = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/kas.AccessService/Rewrap"
            assert self.headers["Authorization"] == "Bearer local-test"
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            claims = json.loads(
                base64.urlsafe_b64decode(
                    data["signedRequestToken"].split(".")[1] + "==="
                )
            )
            request = json.loads(claims["requestBody"])
            grant = request["keyAccess"]
            assert grant["kid"] == KEY_ID and grant["url"] == ORIGIN
            wrapped = base64.b64decode(grant["wrappedKey"])
            dek = box(private, grant["ephemeralPublicKey"]).decrypt(
                wrapped[:12], wrapped[12:], None
            )
            session = ec.generate_private_key(ec.SECP256R1())
            nonce = os.urandom(12)
            encrypted = nonce + box(session, request["clientPublicKey"]).encrypt(
                nonce, dek, None
            )
            response = json.dumps(
                {
                    "entityWrappedKey": base64.b64encode(encrypted).decode(),
                    "sessionPublicKey": session.public_key()
                    .public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode(),
                }
            ).encode()
            calls.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with TemporaryDirectory(prefix="tdf-local-key-parity-") as directory:
        work = Path(directory)
        commands = packaged_commands(root, python_sdk, work)
        public_file = work / "bundle.pub.pem"
        public_file.write_text(public)
        source = work / "payload.bin"
        source.write_bytes(bytes(range(256)) * 12289)
        expected = hashlib.sha256(source.read_bytes()).digest()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for profile in ("java", "spec"):
                for writer in ("rust", "python"):
                    archive = work / f"{writer}-{profile}.tdf"
                    if writer == "rust":
                        subprocess.run(
                            commands[writer]
                            + [
                                "create-spec-p256"
                                if profile == "spec"
                                else "create-p256",
                                str(source),
                                str(archive),
                            ],
                            env={
                                **os.environ,
                                "OTDF_TEST_AUTH_MODE": "public-key",
                                "OTDF_KAS_URL": ORIGIN,
                                "OTDF_TEST_KAS_EC_KEY_ID": KEY_ID,
                                "OTDF_KAS_PUBLIC_KEY_FILE": str(public_file),
                                "OTDF_ATTRIBUTE": ATTRIBUTE,
                                "OTDF_MANIFEST_KAS_URL": "",
                            },
                            check=True,
                        )
                    else:
                        subprocess.run(
                            commands[writer][:2]
                            + [
                                "-c",
                                "from opentdf_sdk import KasConfig, create_tdf; "
                                "from pathlib import Path; "
                                "import sys; create_tdf(sys.argv[1], sys.argv[2], "
                                "kas=KasConfig.from_public_key(sys.argv[3], "
                                "sys.argv[4], Path(sys.argv[5]).read_text()), "
                                "attribute=sys.argv[6], profile=sys.argv[7])",
                                str(source),
                                str(archive),
                                ORIGIN,
                                KEY_ID,
                                str(public_file),
                                ATTRIBUTE,
                                profile,
                            ],
                            check=True,
                        )
                    with ZipFile(archive) as package:
                        name = (
                            "manifest.json" if profile == "spec" else "0.manifest.json"
                        )
                        grant = json.loads(package.read(name))["encryptionInformation"][
                            "keyAccess"
                        ][0]
                        assert (grant["url"], grant["kid"], grant["type"]) == (
                            ORIGIN,
                            KEY_ID,
                            "ec-wrapped",
                        )
                    for reader in ("rust", "python"):
                        output = work / f"{writer}-{profile}-{reader}.bin"
                        subprocess.run(
                            commands[reader] + ["open-p256", str(archive), str(output)],
                            env={
                                **os.environ,
                                "OTDF_TEST_AUTH_MODE": "bearer",
                                "OTDF_KAS_URL": f"http://127.0.0.1:{server.server_port}",
                                "OTDF_ACCESS_TOKEN": "local-test",
                                "OTDF_MANIFEST_KAS_URL": ORIGIN,
                            },
                            check=True,
                        )
                        assert hashlib.sha256(output.read_bytes()).digest() == expected
            assert len(calls) == 8
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
    print(
        "Packaged Rust/Python per-bundle keys: both profiles and "
        "all 8 reader/writer combinations passed"
    )


if __name__ == "__main__":
    main()
