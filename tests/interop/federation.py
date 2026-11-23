"""Prove a new trust-domain member can read an unchanged TDF with Site A offline."""

from __future__ import annotations

import errno
import hashlib
import os
import signal
import socket
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from consumers import packaged_commands
from matrix import JAVA_MANIFEST, SPEC_MANIFEST, invoke, read_archive, sdk_roots
from with_platform import local_docker, platform_binary, platform_site, platform_sources

MANIFEST_ORIGIN = "https://wrapping.example.invalid"


def test_ports(site: dict[str, str]) -> set[int]:
    ports = {int(site["OTDF_TEST_DB_PORT"])}
    for name in ("OTDF_KAS_URL", "OTDF_TEST_IDP_URL"):
        port = urlsplit(site[name]).port
        if port is None:
            raise ValueError(f"test endpoint has no port: {name}")
        ports.add(port)
    if len(ports) != 3:
        raise ValueError("Site requires distinct KAS, IdP, and database ports")
    return ports


def assert_offline(ports: set[int]) -> None:
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", port)) != errno.ECONNREFUSED:
                raise RuntimeError(f"retired site still reachable on port {port}")


def optional_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


def main() -> None:
    rust_sdk, python_sdk = sdk_roots(__doc__ or "")
    local_docker()
    with TemporaryDirectory(prefix="opentdf-federation-") as workspace:
        work = Path(workspace)
        source = platform_sources(optional_path("OTDF_TEST_PLATFORM_SOURCE"), work)
        binary = platform_binary(
            source, optional_path("OTDF_TEST_PLATFORM_BINARY"), work
        )
        drivers = packaged_commands(rust_sdk, python_sdk, work)
        plaintext = bytes(range(256)) * 8193
        payload = work / "input.bin"
        payload.write_bytes(plaintext)
        archives: dict[Path, tuple[str, bytes]] = {}
        enrollment_key = work / "wrapping-key.pem"
        enrollment_ec_key = work / "ec-wrapping-key.pem"
        key_files = {
            "kas-private.pem": enrollment_key,
            "kas-ec-private.pem": enrollment_ec_key,
        }

        with TemporaryDirectory(prefix="producer-", dir=work) as producer_dir:
            producer = Path(producer_dir)
            with platform_site(source, binary, producer) as site_a:
                ports_a = test_ports(site_a)
                for peer, driver in drivers.items():
                    for operation, manifest_name, kid, reader in (
                        ("create", JAVA_MANIFEST, "r1", "open"),
                        ("create-spec", SPEC_MANIFEST, "r1", "open"),
                        ("create-p256", JAVA_MANIFEST, "e1", "open-p256"),
                        ("create-spec-p256", SPEC_MANIFEST, "e1", "open-p256"),
                    ):
                        archive = work / f"{peer}-{operation}.tdf"
                        invoke(
                            peer,
                            driver,
                            operation,
                            payload,
                            archive,
                            unchanged=None,
                            **site_a,
                            OTDF_MANIFEST_KAS_URL=MANIFEST_ORIGIN,
                        )
                        manifest, _ = read_archive(archive, manifest_name)
                        grant = manifest["encryptionInformation"]["keyAccess"][0]
                        if grant["url"] != MANIFEST_ORIGIN or grant["kid"] != kid:
                            raise ValueError(f"{peer} wrote the wrong wrapping grant")
                        archives[archive] = (
                            reader,
                            hashlib.sha256(archive.read_bytes()).digest(),
                        )
                producer_public_keys = {}
                for filename, enrollment in key_files.items():
                    with open(enrollment, "xb", opener=private_file) as private:
                        private.write((producer / filename).read_bytes())
                    producer_public_keys[filename] = public_key(producer / filename)
        assert_offline(ports_a)
        print("Producer KAS, IdP and database are offline", flush=True)

        archive = next(iter(archives))
        with platform_site(
            source,
            binary,
            work / "wrong-key",
            exclude_ports=ports_a,
        ) as unenrolled:
            assert_offline(ports_a)
            if any(
                public_key(work / "wrong-key" / name) == key
                for name, key in producer_public_keys.items()
            ):
                raise ValueError("Wrong-key control reused the trust-domain key")
            for peer, driver in drivers.items():
                for operation in ("open", "open-p256"):
                    sample = next(
                        p for p, (reader, _) in archives.items() if reader == operation
                    )
                    invoke(
                        peer,
                        driver,
                        operation,
                        sample,
                        work / f"{peer}-{operation}-wrong-key.bin",
                        expected_error="Error:" if peer == "rust" else "TDF error:",
                        unchanged=None,
                        **unenrolled,
                        OTDF_MANIFEST_KAS_URL=MANIFEST_ORIGIN,
                    )
        ports_retired = ports_a | test_ports(unenrolled)
        assert_offline(ports_retired)

        with platform_site(
            source,
            binary,
            work / "consumer",
            wrapping_key=enrollment_key,
            ec_wrapping_key=enrollment_ec_key,
            exclude_ports=ports_retired,
        ) as site_b:
            assert_offline(ports_retired)
            if any(
                public_key(work / "consumer" / name) != key
                for name, key in producer_public_keys.items()
            ):
                raise ValueError("Consumer did not enroll the trust-domain keys")

            for peer, driver in drivers.items():
                for artifact, (operation, _) in archives.items():
                    output = work / f"{artifact.stem}-to-{peer}.bin"
                    environment = site_b | {"OTDF_MANIFEST_KAS_URL": MANIFEST_ORIGIN}
                    if operation == "open-p256":
                        environment |= {
                            "OTDF_TEST_AUTH_MODE": "discover-client-credentials",
                            "OTDF_ACCESS_TOKEN": "",
                            "OTDF_KAS_URL": site_a["OTDF_KAS_URL"],
                        }
                    invoke(
                        peer,
                        driver,
                        operation,
                        artifact,
                        output,
                        unchanged=None,
                        **environment,
                    )
                    if output.read_bytes() != plaintext:
                        raise ValueError(f"{peer} opened {artifact.name} incorrectly")
                    print(f"{artifact.stem} → {peer} at Site B passed", flush=True)

                for label, expected, overrides in (
                    (
                        "no-route",
                        "Invalid"
                        if peer == "rust"
                        else "Untrusted manifest KAS origin",
                        {"OTDF_MANIFEST_KAS_URL": ""},
                    ),
                    (
                        "wrong-route",
                        "Invalid"
                        if peer == "rust"
                        else "Untrusted manifest KAS origin",
                        {"OTDF_MANIFEST_KAS_URL": "https://untrusted.example.invalid"},
                    ),
                    (
                        "denied",
                        "PermissionDenied" if peer == "rust" else "KAS denied access",
                        {
                            "OTDF_MANIFEST_KAS_URL": MANIFEST_ORIGIN,
                            "OTDF_ACCESS_TOKEN": site_b["OTDF_DENIED_ACCESS_TOKEN"],
                        },
                    ),
                    (
                        "producer-token",
                        "Authentication" if peer == "rust" else "HTTP 401",
                        {
                            "OTDF_MANIFEST_KAS_URL": MANIFEST_ORIGIN,
                            "OTDF_ACCESS_TOKEN": site_a["OTDF_ACCESS_TOKEN"],
                        },
                    ),
                ):
                    invoke(
                        peer,
                        driver,
                        "open",
                        archive,
                        work / f"{peer}-{label}.bin",
                        expected_error=expected,
                        unchanged=None,
                        **(site_b | overrides),
                    )
                print(
                    f"{peer}: wrong key, route, token and entitlement checks passed",
                    flush=True,
                )

            assert_offline(ports_retired)
            for artifact, (_, digest) in archives.items():
                if hashlib.sha256(artifact.read_bytes()).digest() != digest:
                    raise ValueError(f"{artifact.name} changed during federation")
            print(
                f"All {len(archives)} producer archives are byte-identical", flush=True
            )
        assert_offline(test_ports(site_b) | ports_retired)


def private_file(name: str, flags: int) -> int:
    return os.open(name, flags, 0o600)


def public_key(private_key: Path) -> bytes:
    return subprocess.check_output(
        ["openssl", "pkey", "-in", str(private_key), "-pubout"], timeout=15
    )


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    main()
