from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from zipfile import ZipFile

from consumers import packaged_commands

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
JAVA_MANIFEST = "0.manifest.json"
SPEC_MANIFEST = "manifest.json"
PAYLOAD = "0.payload"


def invoke(
    peer: str,
    driver: list[str],
    operation: str,
    source: Path,
    output: Path,
    *arguments: str | Path,
    expected_error: str | None = None,
    unchanged: bytes | None = None,
    **environment: str,
) -> None:
    args = [operation, str(source), str(output), *map(str, arguments)]
    if peer == "java":
        args = [f"-Dexec.args={shlex.join(args)}"]
        if operation in ("open", "open-features", "open-assertions", "open-p256"):
            driver = [*driver[:-2], "exec:java"]
    result = subprocess.run(
        driver + args,
        env=os.environ | {"OTDF_MANIFEST_KAS_URL": ""} | environment,
        check=False,
        capture_output=expected_error is not None,
        text=True,
        timeout=180,
    )
    if expected_error is None:
        result.check_returncode()
        return
    output_ok = (
        not output.exists()
        if unchanged is None
        else output.exists() and output.read_bytes() == unchanged
    )
    if result.returncode == 0 or not output_ok or expected_error not in result.stderr:
        raise RuntimeError(f"{peer} did not reject {source.name} as expected")


def read_archive(path: Path, manifest_name: str) -> tuple[dict[str, Any], bytes]:
    with ZipFile(path) as archive:
        if sorted(archive.namelist()) != sorted((manifest_name, PAYLOAD)):
            raise ValueError(f"unexpected members in {path.name}")
        return json.loads(archive.read(manifest_name)), archive.read(PAYLOAD)


def write_archive(
    path: Path,
    manifest: dict[str, Any],
    payload: bytes,
    *,
    payload_name: str = PAYLOAD,
    manifest_name: str = SPEC_MANIFEST,
    ambiguous: bool = False,
) -> Path:
    encoded = json.dumps(manifest, separators=(",", ":"))
    with ZipFile(path, "w") as archive:
        archive.writestr(payload_name, payload)
        archive.writestr(manifest_name, encoded)
        if ambiguous:
            archive.writestr(JAVA_MANIFEST, encoded)
    return path


def rejection_cases(
    work: Path,
    archives: dict[str, Path],
    commands: dict[str, list[str]],
    original: bytes,
) -> None:
    denied_token = os.environ["OTDF_DENIED_ACCESS_TOKEN"]
    shared_token = os.environ["OTDF_SHARED_ACCESS_TOKEN"]
    legacy, spec = archives["rust-legacy"], archives["rust-spec"]
    manifest, payload = read_archive(spec, SPEC_MANIFEST)
    ambiguous = write_archive(work / "ambiguous.tdf", manifest, payload, ambiguous=True)
    tampered = write_archive(
        work / "tampered.tdf",
        manifest,
        payload[:12] + bytes([payload[12] ^ 1]) + payload[13:],
    )
    key_access = manifest["encryptionInformation"]["keyAccess"]
    key_access.append(key_access[0].copy())
    multiple_grants = write_archive(work / "multiple-grants.tdf", manifest, payload)
    key_access.pop()

    binding_manifest = copy.deepcopy(manifest)
    binding = binding_manifest["encryptionInformation"]["keyAccess"][0]["policyBinding"]
    binding["hash"] = base64.b64encode(bytes(32)).decode("ascii")
    altered_binding = write_archive(
        work / "altered-binding.tdf", binding_manifest, payload
    )

    root_manifest = copy.deepcopy(manifest)
    root = root_manifest["encryptionInformation"]["integrityInformation"][
        "rootSignature"
    ]
    root["sig"] = base64.b64encode(bytes(32)).decode("ascii")
    altered_root = write_archive(work / "altered-root.tdf", root_manifest, payload)

    manifest["payload"]["url"] = "test-payload.bin"
    renamed = write_archive(
        work / "referenced.tdf", manifest, payload, payload_name="test-payload.bin"
    )
    manifest["payload"]["url"] = PAYLOAD

    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        unavailable_kas = f"http://127.0.0.1:{reserved.getsockname()[1]}"
        key_access[0]["url"] = unavailable_kas
        unavailable = write_archive(work / "unavailable.tdf", manifest, payload)

        for peer, errors in (
            (
                "rust",
                (
                    "Invalid",
                    "Authentication",
                    "PermissionDenied",
                    "transport error",
                    "Error:",
                ),
            ),
            (
                "python",
                (
                    "TDF error:",
                    "HTTP 401",
                    "KAS denied access",
                    "could not be reached",
                    "TDF error:",
                ),
            ),
        ):
            driver = commands[peer]
            output = work / f"{peer}-referenced.bin"
            invoke(peer, driver, "open", renamed, output)
            if output.read_bytes() != original:
                raise ValueError(f"{peer} resolved the wrong payload")
            for path in (ambiguous, tampered, multiple_grants):
                invoke(
                    peer,
                    driver,
                    "open",
                    path,
                    work / "rejected.bin",
                    expected_error=errors[0],
                )
            invoke(
                peer,
                driver,
                "open",
                altered_root,
                work / "root.bin",
                expected_error=errors[0],
            )
            invoke(
                peer,
                driver,
                "open",
                altered_binding,
                work / "binding.bin",
                expected_error=errors[4],
            )
            existing = work / f"{peer}-existing.bin"
            sentinel = b"existing destination"
            existing.write_bytes(sentinel)
            collision = "AlreadyExists" if peer == "rust" else "FileExistsError"
            for path, create in ((legacy, "create"), (spec, "create-spec")):
                invoke(
                    peer,
                    driver,
                    "open",
                    path,
                    existing,
                    expected_error=collision,
                    unchanged=sentinel,
                )
                invoke(
                    peer,
                    driver,
                    create,
                    work / "input.bin",
                    existing,
                    expected_error=collision,
                    unchanged=sentinel,
                )
                shared_output = work / f"{peer}-{path.stem}-shared.bin"
                invoke(
                    peer,
                    driver,
                    "open",
                    path,
                    shared_output,
                    OTDF_ACCESS_TOKEN=shared_token,
                )
                if shared_output.read_bytes() != original:
                    raise ValueError(f"{peer} shared-KAS read returned different bytes")
                invoke(
                    peer,
                    driver,
                    "open",
                    path,
                    work / "invalid-token.bin",
                    expected_error=errors[1],
                    OTDF_ACCESS_TOKEN="invalid",
                )
                invoke(
                    peer,
                    driver,
                    "open",
                    path,
                    work / "denied.bin",
                    expected_error=errors[2],
                    OTDF_ACCESS_TOKEN=denied_token,
                )
            invoke(
                peer,
                driver,
                "open",
                unavailable,
                work / "unavailable.bin",
                expected_error=errors[3],
                OTDF_KAS_URL=unavailable_kas,
            )
            print(
                f"{peer} shared-KAS, payload-reference, and rejection checks passed",
                flush=True,
            )


def empty_round_trips(work: Path, commands: dict[str, list[str]]) -> None:
    source = work / "empty.bin"
    source.touch()
    for writer in ("rust", "python"):
        for profile, operation in (("legacy", "create"), ("spec", "create-spec")):
            artifact = work / f"{writer}-{profile}-empty.tdf"
            invoke(writer, commands[writer], operation, source, artifact)
            for reader in ("rust", "python"):
                output = work / f"{artifact.stem}-to-{reader}.bin"
                invoke(reader, commands[reader], "open", artifact, output)
                if output.read_bytes() != b"":
                    raise ValueError(f"{reader} returned bytes for an empty input")
                print(f"{artifact.stem} → {reader} passed", flush=True)


def compare_feature_archives(
    work: Path,
    commands: dict[str, list[str]],
    archives: dict[Path, str],
    original: bytes,
    operation: str,
    *arguments: Path,
) -> None:
    def compare(reader: str, artifact: Path) -> None:
        output = work / f"{artifact.stem}-to-{reader}.bin"
        invoke(reader, commands[reader], operation, artifact, output, *arguments)
        if output.read_bytes() != original:
            raise ValueError(f"{artifact.name} to {reader} recovered different bytes")
        print(f"{artifact.stem} → {reader} passed", flush=True)

    for reader in ("rust", "python", "go"):
        for artifact in archives:
            compare(reader, artifact)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda artifact: compare("java", artifact),
                (p for p, profile in archives.items() if profile == JAVA_MANIFEST),
            )
        )


def p256_round_trips(
    work: Path, commands: dict[str, list[str]], source: Path, original: bytes
) -> None:
    archives = {}
    for writer, driver in commands.items():
        profiles = ("legacy", "spec") if writer in ("rust", "python") else ("legacy",)
        for profile in profiles:
            artifact = work / f"{writer}-{profile}-p256.tdf"
            manifest_name = SPEC_MANIFEST if profile == "spec" else JAVA_MANIFEST
            invoke(
                writer,
                driver,
                "create-spec-p256" if profile == "spec" else "create-p256",
                source,
                artifact,
            )
            manifest, _ = read_archive(artifact, manifest_name)
            (grant,) = manifest["encryptionInformation"]["keyAccess"]
            if (
                grant["type"] != "ec-wrapped"
                or grant["kid"] != os.environ["OTDF_TEST_KAS_EC_KEY_ID"]
                or not grant["ephemeralPublicKey"].startswith(
                    "-----BEGIN PUBLIC KEY-----"
                )
                or len(base64.b64decode(grant["wrappedKey"], validate=True)) != 60
            ):
                raise ValueError(
                    f"{artifact.name} has an unexpected P-256 key access object"
                )
            archives[artifact] = manifest_name
    compare_feature_archives(work, commands, archives, original, "open-p256")

    artifact = work / "java-legacy-p256.tdf"
    for reader in ("rust", "python"):
        output = work / f"{reader}-p256-with-rsa-session.bin"
        invoke(reader, commands[reader], "open", artifact, output)
        if output.read_bytes() != original:
            raise ValueError(
                f"{reader} did not recover the P-256 TDF with an RSA session"
            )
        invoke(
            reader,
            commands[reader],
            "open-p256",
            artifact,
            work / f"{reader}-p256-denied.bin",
            expected_error="PermissionDenied"
            if reader == "rust"
            else "KAS denied access",
            OTDF_ACCESS_TOKEN=os.environ["OTDF_DENIED_ACCESS_TOKEN"],
        )
    print("P-256 KAS denial and RSA session compatibility passed", flush=True)


def connection_round_trips(
    work: Path, commands: dict[str, list[str]], source: Path, original: bytes
) -> None:
    missing = "https://unused.example.invalid"
    modes = {
        "discover": {"OTDF_KAS_URL": missing},
        "client-credentials": {"OTDF_ACCESS_TOKEN": ""},
        "discover-client-credentials": {
            "OTDF_ACCESS_TOKEN": "",
            "OTDF_KAS_URL": missing,
        },
    }
    for peer in ("rust", "python"):
        for mode, environment in modes.items():
            path = work / f"{peer}-{mode}"
            artifact = path.with_suffix(".tdf")
            output = path.with_suffix(".bin")
            invoke(
                peer,
                commands[peer],
                "create",
                source,
                artifact,
                OTDF_TEST_AUTH_MODE=mode,
                unchanged=None,
                **environment,
            )
            manifest, _ = read_archive(artifact, JAVA_MANIFEST)
            (grant,) = manifest["encryptionInformation"]["keyAccess"]
            if grant["url"] != os.environ["OTDF_KAS_URL"]:
                raise ValueError(f"{peer} wrote an unexpected KAS origin for {mode}")
            # This also exercises EC session rewrap of an RSA-wrapped grant.
            invoke(
                peer,
                commands[peer],
                "open-p256",
                artifact,
                output,
                OTDF_TEST_AUTH_MODE=mode,
                unchanged=None,
                **environment,
            )
            if output.read_bytes() != original:
                raise ValueError(f"{peer} recovered different bytes using {mode}")
            print(f"{peer} {mode} passed", flush=True)

        for label, failure in (
            ("wrong-secret", {"OTDF_CLIENT_SECRET": "invalid-local-client-secret"}),
            (
                "wrong-issuer",
                {"OTDF_TEST_ISSUER": f"{os.environ['OTDF_TEST_ISSUER']}-other"},
            ),
        ):
            invoke(
                peer,
                commands[peer],
                "open",
                artifact,
                work / f"{peer}-{label}.bin",
                expected_error="Error:" if peer == "rust" else "TDF error:",
                unchanged=None,
                OTDF_TEST_AUTH_MODE="discover-client-credentials",
                OTDF_ACCESS_TOKEN="",
                **failure,
            )
    print("Wrong OAuth secret and platform issuer were rejected", flush=True)


def feature_round_trips(
    work: Path, commands: dict[str, list[str]], attributes: list[str]
) -> None:
    source = work / "input.bin"
    original = source.read_bytes()
    metadata = work / "metadata.txt"
    metadata.write_bytes("release notes • révision 2\n".encode())
    archives = {}
    for writer in commands:
        profiles = ("legacy", "spec") if writer in ("rust", "python") else ("legacy",)
        for profile in profiles:
            artifact = work / f"{writer}-{profile}-features.tdf"
            invoke(
                writer,
                commands[writer],
                "create-spec-features" if profile == "spec" else "create-features",
                source,
                artifact,
                metadata,
                *attributes,
            )
            manifest_name = SPEC_MANIFEST if profile == "spec" else JAVA_MANIFEST
            manifest, _ = read_archive(artifact, manifest_name)
            encryption = manifest["encryptionInformation"]
            policy = json.loads(base64.b64decode(encryption["policy"], validate=True))
            values = [value["attribute"] for value in policy["body"]["dataAttributes"]]
            grants = encryption["keyAccess"]
            if sorted(values) != sorted(attributes) or len(grants) != 1:
                raise ValueError(f"{artifact.name} has unexpected policy or KAS grants")
            envelope = json.loads(
                base64.b64decode(grants[0]["encryptedMetadata"], validate=True)
            )
            iv = base64.b64decode(envelope["iv"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            if len(iv) != 12 or ciphertext[:12] != iv or len(ciphertext) <= 28:
                raise ValueError(f"{artifact.name} has invalid metadata framing")
            if metadata.read_text().strip() in json.dumps(manifest, ensure_ascii=False):
                raise ValueError(f"{artifact.name} exposes the plaintext metadata")
            archives[artifact] = manifest_name

    compare_feature_archives(
        work, commands, archives, original, "open-features", metadata
    )

    one_attribute = work / "one-all-of-value.tdf"
    invoke(
        "rust",
        commands["rust"],
        "create",
        source,
        one_attribute,
        OTDF_ATTRIBUTE=attributes[0],
    )
    partial_token = os.environ["OTDF_SHARED_ACCESS_TOKEN"]
    for reader in ("rust", "python"):
        output = work / f"{reader}-partial-control.bin"
        invoke(
            reader,
            commands[reader],
            "open",
            one_attribute,
            output,
            OTDF_ACCESS_TOKEN=partial_token,
        )
        if output.read_bytes() != original:
            raise ValueError(f"{reader} failed the partial-entitlement control")

    for name in ("java-legacy-features.tdf", "rust-spec-features.tdf"):
        artifact = work / name
        manifest, payload = read_archive(artifact, archives[artifact])
        grant = manifest["encryptionInformation"]["keyAccess"][0]
        envelope = json.loads(base64.b64decode(grant["encryptedMetadata"]))
        modified_ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        modified_ciphertext[-1] ^= 1
        envelope["ciphertext"] = base64.b64encode(modified_ciphertext).decode("ascii")
        grant["encryptedMetadata"] = base64.b64encode(
            json.dumps(envelope).encode()
        ).decode("ascii")
        tampered = write_archive(
            work / f"{artifact.stem}-tampered.tdf",
            manifest,
            payload,
            manifest_name=archives[artifact],
        )
        for reader in ("rust", "python"):
            for label, token in (
                ("partial", partial_token),
                ("none", os.environ["OTDF_DENIED_ACCESS_TOKEN"]),
            ):
                invoke(
                    reader,
                    commands[reader],
                    "open-features",
                    artifact,
                    work / f"{reader}-{label}.bin",
                    metadata,
                    expected_error="PermissionDenied"
                    if reader == "rust"
                    else "KAS denied access",
                    OTDF_ACCESS_TOKEN=token,
                )
            invoke(
                reader,
                commands[reader],
                "open",
                tampered,
                work / f"{reader}-metadata-tampered.bin",
                expected_error="metadata" if reader == "rust" else "TDF error:",
            )
    print("All-of entitlement and encrypted metadata tamper checks passed", flush=True)


def assertion_round_trips(
    work: Path, commands: dict[str, list[str]], source: Path, original: bytes
) -> None:
    def generate_key(name: str) -> tuple[Path, Path]:
        private = work / f"{name}-private.pem"
        public = work / f"{name}-public.pem"
        for args in (
            [
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ],
            ["pkey", "-in", str(private), "-pubout", "-out", str(public)],
        ):
            subprocess.run(
                ["openssl", *args], check=True, capture_output=True, timeout=30
            )
        return private, public

    private, public = generate_key("publisher")
    _, wrong_key = generate_key("wrong-publisher")
    archives = {}
    for writer in commands:
        profiles = ("legacy", "spec") if writer in ("rust", "python") else ("legacy",)
        for profile in profiles:
            artifact = work / f"{writer}-{profile}-assertions.tdf"
            invoke(
                writer,
                commands[writer],
                "create-spec-assertions" if profile == "spec" else "create-assertions",
                source,
                artifact,
                private,
            )
            manifest_name = SPEC_MANIFEST if profile == "spec" else JAVA_MANIFEST
            manifest, _ = read_archive(artifact, manifest_name)
            assertions = manifest["assertions"]
            algorithms = {}
            for assertion in assertions:
                header = assertion["binding"]["signature"].split(".")[0]
                protected = json.loads(
                    base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
                )
                algorithms[assertion["id"]] = protected["alg"]
            if len(assertions) != 2 or algorithms != {
                "tdf-binding": "HS256",
                "publisher": "RS256",
            }:
                raise ValueError(f"{artifact.name} has unexpected assertions")
            archives[artifact] = manifest_name
    compare_feature_archives(
        work, commands, archives, original, "open-assertions", public
    )

    java, _ = read_archive(work / "java-legacy-assertions.tdf", JAVA_MANIFEST)
    publisher = next(item for item in java["assertions"] if item["id"] == "publisher")
    spec = work / "rust-spec-assertions.tdf"
    manifest, payload = read_archive(spec, SPEC_MANIFEST)
    tampered = copy.deepcopy(manifest)
    tampered["assertions"][0]["statement"]["value"] += " changed"
    transplanted = copy.deepcopy(manifest)
    transplanted["assertions"] = [transplanted["assertions"][0], publisher]
    missing = copy.deepcopy(manifest)
    missing["assertions"] = [missing["assertions"][0]]
    cases = {
        label: write_archive(work / f"assertions-{label}.tdf", altered, payload)
        for label, altered in (
            ("tampered", tampered),
            ("transplanted", transplanted),
            ("missing", missing),
        )
    }
    for reader in ("rust", "python"):
        output = work / f"{reader}-rejected-assertions.bin"
        before = set(work.iterdir())
        for artifact, key in [
            *((artifact, public) for artifact in cases.values()),
            (spec, wrong_key),
        ]:
            invoke(
                reader,
                commands[reader],
                "open-assertions",
                artifact,
                output,
                key,
                expected_error="Invalid" if reader == "rust" else "TDF error:",
            )
        if set(work.iterdir()) != before:
            raise ValueError(f"{reader} left output files after rejecting an assertion")
    print(
        "Assertion tamper, transplant, missing ID, and wrong-key checks passed",
        flush=True,
    )


def check_shared_harness(rust_root: Path, python_root: Path) -> None:
    shared = (
        "tests/interop/README.md",
        "tests/interop/consumers.py",
        "tests/interop/matrix.py",
        "tests/interop/matrix.sh",
        "tests/interop/with_platform.py",
        "tests/interop/go/README.md",
        "tests/interop/go/go.mod",
        "tests/interop/go/go.sum",
        "tests/interop/go/main.go",
        "tests/interop/java/README.md",
        "tests/interop/java/local-kas.md",
        "tests/interop/java/pom.xml",
        "tests/interop/java/src/main/java/TdfDriver.java",
        "tests/interop/federation.md",
        "tests/interop/federation.py",
        "tests/interop/large_payloads.py",
        "tests/conformance/README.md",
        "tests/vectors/zip-profile-v1.json",
        "docs/capabilities.md",
        "docs/conformance.md",
    )
    for path in shared:
        if (rust_root / path).read_bytes() != (python_root / path).read_bytes():
            raise ValueError(f"shared test harness differs between SDKs: {path}")


def sdk_roots(description: str) -> tuple[Path, Path]:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "python_sdk",
        type=Path,
        nargs="?",
        default=ROOT
        if (ROOT / "pyproject.toml").is_file()
        else ROOT.parent / "opentdf-python-sdk",
    )
    parser.add_argument(
        "--rust-sdk",
        type=Path,
        default=ROOT
        if (ROOT / "Cargo.toml").is_file()
        else ROOT.parent / "opentdf-rust-sdk",
    )
    args = parser.parse_args()
    python_root = args.python_sdk.resolve()
    rust_root = args.rust_sdk.resolve()
    check_shared_harness(rust_root, python_root)
    return rust_root, python_root


def main() -> None:
    rust_root, python_root = sdk_roots("Run the packaged SDK interoperability matrix.")
    for name in (
        "OTDF_ACCESS_TOKEN",
        "OTDF_SHARED_ACCESS_TOKEN",
        "OTDF_DENIED_ACCESS_TOKEN",
    ):
        if not os.environ.get(name):
            raise SystemExit(f"Set {name} before running the live matrix")
    with TemporaryDirectory(prefix="opentdf-matrix-") as temporary:
        work = Path(temporary)
        source = work / "input.bin"
        original = bytes(range(256)) * 8193
        source.write_bytes(original)
        subprocess.run(
            ["go", "build", "-mod=readonly", "-o", str(work / "go-driver"), "."],
            cwd=HERE / "go",
            env=os.environ | {"CGO_ENABLED": "0"},
            check=True,
            timeout=600,
        )
        commands = packaged_commands(rust_root, python_root, work)
        commands["go"] = [str(work / "go-driver")]
        commands["java"] = [
            "mvn",
            "-q",
            "-f",
            str(HERE / "java/pom.xml"),
            "compile",
            "exec:java",
        ]
        if os.environ.get("OTDF_TEST_KAS_EC_KEY_ID"):
            p256_round_trips(work, commands, source, original)
            if os.environ.get("OTDF_TEST_ISSUER"):
                connection_round_trips(work, commands, source, original)
        assertion_round_trips(work, commands, source, original)
        archives = {}
        for peer in commands:
            for profile in (
                ("legacy", "spec") if peer in ("rust", "python") else ("legacy",)
            ):
                artifact = work / f"{peer}-{profile}.tdf"
                invoke(
                    peer,
                    commands[peer],
                    "create-spec" if profile == "spec" else "create",
                    source,
                    artifact,
                )
                archives[f"{peer}-{profile}"] = artifact
                manifest, _ = read_archive(
                    artifact, SPEC_MANIFEST if profile == "spec" else JAVA_MANIFEST
                )
                if profile == "spec":
                    binding = manifest["encryptionInformation"]["keyAccess"][0][
                        "policyBinding"
                    ]
                    if (
                        manifest["payload"].get("tdf_spec_version") != "4.3.0"
                        or "schemaVersion" in manifest
                        or len(base64.b64decode(binding["hash"], validate=True)) != 32
                    ):
                        raise ValueError(f"unexpected spec manifest in {artifact.name}")

        def compare(reader: str, writer: str) -> None:
            output = work / f"{writer}-to-{reader}.bin"
            invoke(reader, commands[reader], "open", archives[writer], output)
            if output.read_bytes() != original:
                raise ValueError(f"{writer} to {reader} recovered different bytes")
            print(f"{writer} → {reader} passed", flush=True)

        for reader in ("rust", "python", "go"):
            for writer in archives:
                compare(reader, writer)
        rejection_cases(work, archives, commands, original)
        empty_round_trips(work, commands)

        # Java is already compiled. Run its independent reads concurrently.
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda writer: compare("java", writer),
                    [name for name in archives if name.endswith("-legacy")],
                )
            )
        if all_of_attributes := os.environ.get("OTDF_TEST_ALL_OF_ATTRIBUTES"):
            feature_round_trips(work, commands, all_of_attributes.splitlines())


if __name__ == "__main__":
    main()
