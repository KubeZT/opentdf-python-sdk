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
        if operation in ("open", "open-features"):
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

    def compare(reader: str, artifact: Path) -> None:
        output = work / f"{artifact.stem}-to-{reader}.bin"
        invoke(reader, commands[reader], "open-features", artifact, output, metadata)
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
