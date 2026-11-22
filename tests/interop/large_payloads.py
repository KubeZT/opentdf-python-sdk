"""Exercise packaged SDKs with generated large files and a live KAS."""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_STORED, ZipFile

from consumers import packaged_commands
from matrix import JAVA_MANIFEST, PAYLOAD, SPEC_MANIFEST, invoke, sdk_roots

MIB = 1024 * 1024
GIB = 1024 * MIB
ZIP32_MAX = (1 << 32) - 1
MAX_RSS = 128 * MIB
MAX_RSS_GROWTH = 32 * MIB

# Each probe runs one SDK process, so the result excludes the test harness,
# package builders and other SDK operations. Darwin reports bytes, Linux KiB.
RSS_PROBE = """
import resource
import subprocess
import sys

subprocess.run(sys.argv[2:], stdout=sys.stderr, check=True, timeout=int(sys.argv[1]))
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(peak if sys.platform == "darwin" else peak * 1024)
"""


def generate(path: Path, length: int, *, sparse: bool = False) -> None:
    if sparse:
        with path.open("wb") as output:
            for index, offset in enumerate(range(0, length, GIB)):
                output.seek(offset)
                marker = b"TDF test chunk" + index.to_bytes(8, "big")
                output.write(marker[: length - offset])
            output.truncate(length)
        return
    block = random.Random(0x544446).randbytes(MIB - 8)
    with path.open("wb") as output:
        for index, offset in enumerate(range(0, length, MIB)):
            chunk = index.to_bytes(8, "big") + block
            output.write(chunk[: min(MIB, length - offset)])


def digest(path: Path) -> bytes:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            sha.update(chunk)
    return sha.digest()


def run_measured(
    peer: str,
    driver: list[str],
    operation: str,
    source: Path,
    output: Path,
    *,
    timeout: int = 600,
) -> int:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            RSS_PROBE,
            str(timeout),
            *driver,
            operation,
            str(source),
            str(output),
        ],
        env=os.environ | {"OTDF_MANIFEST_KAS_URL": ""},
        stdout=subprocess.PIPE,
        check=True,
        text=True,
        timeout=timeout + 10,
    )
    peak = int(result.stdout)
    print(
        f"{peer} {operation} {source.name}: {peak / MIB:.1f} MiB peak RSS", flush=True
    )
    if not 0 < peak <= MAX_RSS:
        raise RuntimeError(f"{peer} {operation} exceeded the 128 MiB RSS limit")
    return peak


def tamper(source: Path, destination: Path, manifest: str) -> None:
    # Give the altered payload a valid ZIP CRC so the SDK reaches AEAD checking.
    with ZipFile(source) as original, ZipFile(destination, "w") as corrupt:
        size = original.getinfo(PAYLOAD).file_size
        changed_byte = size - 17
        with original.open(PAYLOAD) as inp, corrupt.open(PAYLOAD, "w") as out:
            offset = 0
            for chunk in iter(lambda: inp.read(MIB), b""):
                if offset <= changed_byte < offset + len(chunk):
                    altered = bytearray(chunk)
                    altered[changed_byte - offset] ^= 1
                    out.write(altered)
                else:
                    out.write(chunk)
                offset += len(chunk)
        corrupt.writestr(manifest, original.read(manifest))


def check_failures(
    work: Path, peer: str, driver: list[str], archive: Path, manifest: str
) -> None:
    malformed = work / "truncated.tdf"
    corrupted = work / "late-tamper.tdf"
    shutil.copyfile(archive, malformed)
    with malformed.open("r+b") as cut:
        cut.truncate(malformed.stat().st_size - 1)
    tamper(archive, corrupted, manifest)

    output = work / "must-not-exist.bin"
    existing = work / "existing.bin"
    sentinel = b"existing output"
    existing.write_bytes(sentinel)
    before = set(work.iterdir())
    invalid = "Invalid" if peer == "rust" else "TDF error:"
    denied = "PermissionDenied" if peer == "rust" else "KAS denied access"
    collision = "AlreadyExists" if peer == "rust" else "FileExistsError"
    integrity = (
        "segment authentication failed"
        if peer == "rust"
        else "Invalid or unauthenticated TDF"
    )
    invoke(peer, driver, "open", corrupted, output, expected_error=integrity)
    invoke(peer, driver, "open", malformed, output, expected_error=invalid)
    invoke(
        peer,
        driver,
        "open",
        archive,
        output,
        expected_error=denied,
        OTDF_ACCESS_TOKEN=os.environ["OTDF_DENIED_ACCESS_TOKEN"],
    )
    invoke(
        peer,
        driver,
        "open",
        archive,
        existing,
        expected_error=collision,
        unchanged=sentinel,
    )
    if set(work.iterdir()) != before:
        raise RuntimeError(f"{peer} left temporary files after a failed large read")
    print(f"{peer} rejected corrupt or unauthorized input without output", flush=True)
    malformed.unlink()
    corrupted.unlink()
    existing.unlink()


def check_size(
    work: Path,
    drivers: dict[str, list[str]],
    length: int,
    *,
    run_failures: bool = False,
    zip64: bool = False,
    adaptive: bool = False,
) -> dict[tuple[str, str, str], int]:
    print(f"Testing generated {length} byte payload", flush=True)
    source = work / f"{length}-bytes.bin"
    generate(source, length, sparse=adaptive)
    expected = digest(source)
    measured = {}
    timeout = 1800 if adaptive else 600
    for writer, driver in drivers.items():
        other = "python" if writer == "rust" else "rust"
        for profile, operation, manifest in (
            ("legacy", "create", JAVA_MANIFEST),
            ("spec", "create-spec", SPEC_MANIFEST),
        ):
            if zip64 and (writer, profile) not in {
                ("rust", "legacy"),
                ("python", "spec"),
            }:
                continue
            archive = work / f"{writer}-{profile}-{length}.tdf"
            measured[(writer, profile, "create")] = run_measured(
                writer, driver, operation, source, archive, timeout=timeout
            )

            with ZipFile(archive) as container:
                if set(container.namelist()) != {PAYLOAD, manifest}:
                    raise ValueError(f"{archive.name}: unexpected ZIP entries")
                payload = container.getinfo(PAYLOAD)
                if payload.compress_type != ZIP_STORED:
                    raise ValueError(f"{archive.name}: payload is not stored")
                if zip64 and (
                    payload.file_size <= ZIP32_MAX or payload.extract_version < 45
                ):
                    raise ValueError(f"{archive.name} has no large ZIP64 member")
                if adaptive:
                    info = json.loads(container.read(manifest))[
                        "encryptionInformation"
                    ]["integrityInformation"]
                    segment_size = info["segmentSizeDefault"]
                    if segment_size <= 2 * MIB:
                        raise ValueError(f"{archive.name} did not use adaptive sizing")
                    print(
                        f"{writer} used {segment_size / MIB:.0f} MiB segments",
                        flush=True,
                    )

            for reader in drivers if zip64 and not adaptive else (other,):
                output = work / f"{archive.stem}-to-{reader}.bin"
                measured[(reader, profile, "open")] = run_measured(
                    reader, drivers[reader], "open", archive, output, timeout=timeout
                )
                if output.stat().st_size != length or digest(output) != expected:
                    raise ValueError(f"{writer} to {reader} recovered different bytes")
                output.unlink()

            if run_failures and profile == "spec":
                check_failures(work, other, drivers[other], archive, manifest)
            archive.unlink()
    source.unlink()
    return measured


def main() -> None:
    rust_sdk, python_sdk = sdk_roots(__doc__ or "")
    if sys.platform not in {"darwin", "linux"}:
        raise SystemExit("Peak RSS measurements require macOS or Linux")
    for name in ("OTDF_ACCESS_TOKEN", "OTDF_DENIED_ACCESS_TOKEN"):
        if not os.environ.get(name):
            raise SystemExit(f"Set {name} by running the local KAS test harness")

    with TemporaryDirectory(prefix="opentdf-large-") as temporary:
        work = Path(temporary)
        drivers = packaged_commands(rust_sdk, python_sdk, work, release=True)
        baseline = check_size(work, drivers, 80 * MIB + 17, run_failures=True)
        larger = check_size(work, drivers, 256 * MIB + 17)
        for test, peak in larger.items():
            if peak - baseline[test] > MAX_RSS_GROWTH:
                raise RuntimeError(f"{test} RSS grew by more than 32 MiB")
        print("All 80 and 256 MiB peak RSS bounds passed", flush=True)

        if os.environ.get("OTDF_TEST_ZIP64") == "1":
            length = 8 * GIB + 1
            if shutil.disk_usage(work).free < 3 * length + 512 * MIB:
                raise RuntimeError(
                    "The ZIP64 test needs at least 24.5 GiB of free space"
                )
            zip64_peaks = check_size(work, drivers, length, zip64=True)
            for test, peak in zip64_peaks.items():
                if peak - larger[test] > MAX_RSS_GROWTH:
                    raise RuntimeError(f"{test} ZIP64 RSS grew by more than 32 MiB")
            print("Both SDKs wrote ZIP64 and read both 8 GiB + 1 byte TDFs", flush=True)

        if os.environ.get("OTDF_TEST_HUNDREDS_GIB") == "1":
            length = 256 * GIB
            # The source is sparse. The encrypted archive and recovered output
            # are dense, and both are required during an open operation.
            if shutil.disk_usage(work).free < 2 * length + GIB:
                raise RuntimeError(
                    "The 256 GiB test needs at least 513 GiB of free space"
                )
            check_size(work, drivers, length, zip64=True, adaptive=True)
            print("Both directions passed on a 256 GiB adaptive TDF", flush=True)


if __name__ == "__main__":
    main()
