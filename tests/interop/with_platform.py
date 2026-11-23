"""Run integration tests against a fresh, loopback-only OpenTDF platform."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Collection, Iterator
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

PLATFORM_TAG = "service/v0.31.0"
PLATFORM_COMMIT = "45a10adbe424b962eefc13e6d827226df3ce3939"
KEYCLOAK_IMAGE = (
    "ghcr.io/opentdf/keycloak-standard:26.4.0"
    "@sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd"
)
POSTGRES_IMAGE = (
    "postgres:15-alpine"
    "@sha256:e18480a22d6e48f4d816a6696769b1ec09ac73a824c5649e49c7d8b684913f3d"
)
CLIENT_ID = "opentdf-sdk"
SHARED_ID = "opentdf-shared-reader"
DENIED_ID = "opentdf-denied"
CLIENT_SECRET = "secret"
ATTRIBUTE = "https://example.com/attr/attr1/value/value1"
HTTP = build_opener(ProxyHandler({}))


def checked_replace(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise ValueError(
            f"unexpected data in pinned fixture near {before.splitlines()[0]!r}"
        )
    return source.replace(before, after, 1)


def platform_sources(source: Path | None, work: Path) -> Path:
    if source is not None:
        return source.resolve()
    checkout = work / "platform-source"
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            PLATFORM_TAG,
            "https://github.com/opentdf/platform.git",
            str(checkout),
        ],
        check=True,
        timeout=180,
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        text=True,
        timeout=10,
    ).strip()
    if commit != PLATFORM_COMMIT:
        raise ValueError(f"unexpected OpenTDF checkout commit {commit}")
    return checkout


def platform_binary(source: Path, binary: Path | None, work: Path) -> Path:
    if binary is not None:
        return binary.resolve(strict=True)
    output = work / "opentdf"
    subprocess.run(
        ["go", "build", "-mod=readonly", "-o", str(output), "./service"],
        cwd=source,
        env={
            **os.environ,
            "CGO_ENABLED": "0",
            "GOTOOLCHAIN": "go1.26.10",
            "GOWORK": "auto",
        },
        check=True,
        timeout=600,
    )
    return output


def local_docker() -> None:
    host = os.environ.get("DOCKER_HOST")
    if not host or os.environ.get("DOCKER_CONTEXT"):
        host = subprocess.check_output(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            text=True,
            timeout=15,
        ).strip()
    if not host.startswith("unix://"):
        raise ValueError(
            "the test runner needs a local Docker context with a Unix socket"
        )


def compose_file(work: Path, keycloak_port: str, postgres_port: str) -> Path:
    path = work / "compose.json"
    path.write_text(
        json.dumps(
            {
                "services": {
                    "keycloak": {
                        "image": KEYCLOAK_IMAGE,
                        "command": ["start-dev"],
                        "environment": {
                            "KC_HTTP_RELATIVE_PATH": "/auth",
                            "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
                            "KC_BOOTSTRAP_ADMIN_PASSWORD": "changeme",
                            "JAVA_OPTS_APPEND": "-XX:UseSVE=0",
                        },
                        "ports": [f"127.0.0.1:{keycloak_port}:8080"],
                    },
                    "postgres": {
                        "image": POSTGRES_IMAGE,
                        "environment": {
                            "POSTGRES_USER": "postgres",
                            "POSTGRES_PASSWORD": "changeme",
                            "POSTGRES_DB": "opentdf",
                        },
                        "ports": [f"127.0.0.1:{postgres_port}:5432"],
                    },
                },
            },
        ),
        encoding="utf-8",
    )
    return path


def compose_port(compose: list[str], service: str, port: str) -> int:
    address = subprocess.check_output(
        [*compose, "port", service, port],
        text=True,
        timeout=15,
    ).strip()
    host, _, bound = address.rpartition(":")
    if host != "127.0.0.1" or not bound.isdigit():
        raise ValueError(f"expected a loopback endpoint for {service}")
    return int(bound)


def reserve_port(exclude_ports: Collection[int]) -> socket.socket:
    for _ in range(128):
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", 0))
        except OSError:
            listener.close()
            raise
        if listener.getsockname()[1] not in exclude_ports:
            return listener
        listener.close()
    raise OSError("could not reserve a fresh loopback port")


def wait_until(probe: Callable[[], bool], label: str, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if probe():
                return
        except (URLError, OSError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.5)
    raise TimeoutError(f"{label} was not ready after {timeout}s")


def endpoint_ready(url: str) -> bool:
    with HTTP.open(url, timeout=3) as response:
        return bool(response.status == 200)


def suite_timeout() -> int:
    return 10800 if os.environ.get("OTDF_TEST_HUNDREDS_GIB") == "1" else 1500


def prepare_fixtures(
    source: Path, work: Path, platform: str, keycloak: str, db: int
) -> None:
    config = (source / "opentdf-dev.yaml").read_text()
    config = checked_replace(
        config,
        "  port: 8080\n",
        f"  host: 127.0.0.1\n  port: {platform.rsplit(':', 1)[1]}\n",
    )
    config = checked_replace(config, "  level: debug\n", "  level: info\n")
    config = checked_replace(
        config, "      ec_tdf_enabled: false\n", "      ec_tdf_enabled: true\n"
    )
    config = config.replace("http://localhost:8080", platform).replace(
        "http://localhost:8888", keycloak
    )
    (work / "opentdf.yaml").write_text(
        f"db:\n  host: 127.0.0.1\n  port: {db}\n{config}"
    )

    realm = (source / "service/cmd/keycloak_data.yaml").read_text()
    realm = realm.replace("http://localhost:8080", platform).replace(
        "http://localhost:8888", keycloak
    )
    realm = checked_replace(
        realm,
        "      realm: opentdf\n",
        f"      realm: opentdf\n      accessTokenLifespan: {suite_timeout() + 300}\n",
    )
    marker = f"      - client:\n          clientID: {CLIENT_ID}\n"
    start = realm.index(marker)
    end = realm.index("      - client:\n", start + len(marker))
    block = realm[start:end]
    realm = checked_replace(
        realm,
        block,
        block
        + block.replace(CLIENT_ID, SHARED_ID)
        + block.replace(CLIENT_ID, DENIED_ID),
    )
    (work / "keycloak.yaml").write_text(realm)

    policy_path = Path("service/internal/fixtures/policy_fixtures.yaml")
    policy = checked_replace(
        (source / policy_path).read_text(),
        f"                      - {CLIENT_ID}\n",
        f"                      - {CLIENT_ID}\n                      - {SHARED_ID}\n",
    )
    full_condition = "48a0691b-f033-4414-ba71-f755760e387c"
    policy = checked_replace(
        policy,
        "    subject_condition_sdk_client:\n",
        f"""    subject_condition_sdk_all_of:
      id: {full_condition}
      condition:
        subjectSets:
          - conditionGroups:
              - booleanOperator: CONDITION_BOOLEAN_TYPE_ENUM_OR
                conditions:
                  - subjectExternalSelectorValue: ".clientId"
                    operator: SUBJECT_MAPPING_OPERATOR_ENUM_IN
                    subjectExternalValues:
                      - {CLIENT_ID}
    subject_condition_sdk_client:
""",
    )
    # Both readers have value1. Only the primary identity has value2.
    for value, mapping, attribute, condition in (
        (
            "value1",
            "6e1fdf61-b260-4e6e-a1a5-b32e6bf4d8d1",
            "0fd363db-27b1-4210-b77b-8c82fe044d41",
            "86621a00-b63e-42e9-bea5-40ba52d98ede",
        ),
        (
            "value2",
            "c52be6c5-b14b-4f18-b32a-055c418d1d71",
            "81f643f8-e050-4b97-a005-b61294d4c8bb",
            full_condition,
        ),
    ):
        policy = checked_replace(
            policy,
            "    subject_mapping_sdk_attribute1:\n",
            f"""    subject_mapping_sdk_all_of_{value}:
      id: {mapping}
      attribute_value_id: {attribute}
      subject_condition_set_id: {condition}
    subject_mapping_sdk_attribute1:
""",
        )
        policy = checked_replace(
            policy,
            "    subject_mapping_sdk_attribute1_read:\n",
            f"""    subject_mapping_sdk_all_of_{value}_read:
      subject_mapping_id: {mapping}
      action_name: read
    subject_mapping_sdk_all_of_{value}_create:
      subject_mapping_id: {mapping}
      action_name: create
    subject_mapping_sdk_attribute1_read:
""",
        )
    (work / policy_path.parent).mkdir(parents=True)
    (work / policy_path).write_text(policy)


def generate_keys(
    work: Path, wrapping_key: Path | None, ec_wrapping_key: Path | None
) -> None:
    for filename, enrolled_key, command in (
        (
            "kas-private.pem",
            wrapping_key,
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        ),
        (
            "kas-ec-private.pem",
            ec_wrapping_key,
            ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
        ),
    ):
        if enrolled_key is None:
            subprocess.run(
                ["openssl", *command, "-out", filename],
                cwd=work,
                check=True,
                capture_output=True,
                timeout=30,
            )
        else:
            with os.fdopen(
                os.open(work / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                "wb",
            ) as key:
                key.write(enrolled_key.read_bytes())
    for command in (
        ["rsa", "-in", "kas-private.pem", "-pubout", "-out", "kas-cert.pem"],
        [
            "req",
            "-new",
            "-x509",
            "-key",
            "kas-ec-private.pem",
            "-subj",
            "/CN=kas",
            "-days",
            "1",
            "-out",
            "kas-ec-cert.pem",
        ],
    ):
        subprocess.run(
            ["openssl", *command], cwd=work, check=True, capture_output=True, timeout=30
        )


def fixture_token(keycloak: str, client_id: str) -> str:
    url = f"{keycloak}/auth/realms/opentdf/protocol/openid-connect/token"
    request = Request(
        url,
        data=urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": CLIENT_SECRET,
            }
        ).encode(),
    )
    with HTTP.open(request, timeout=10) as response:
        token = json.load(response)["access_token"]
    if not isinstance(token, str) or not token:
        raise ValueError(f"missing token for {client_id}")
    return token


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@contextlib.contextmanager
def platform_site(
    source: Path,
    binary: Path,
    work: Path,
    *,
    wrapping_key: Path | None = None,
    ec_wrapping_key: Path | None = None,
    exclude_ports: Collection[int] = (),
) -> Iterator[dict[str, str]]:
    """Start an isolated test site and return its fixture connection settings."""
    local_docker()
    work = work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise ValueError("the platform site work directory must be empty")
    project = f"opentdf-tests-{uuid.uuid4().hex[:12]}"
    platform_process = None
    with contextlib.ExitStack() as reserved:
        keycloak_publish, postgres_publish = "", ""
        if exclude_ports:
            # Compose can allocate any free port. Pick two distinct ports first
            # when a previous site's endpoints must remain unused.
            with (
                reserve_port(exclude_ports) as keycloak_socket,
                reserve_port(exclude_ports) as postgres_socket,
            ):
                keycloak_publish = str(keycloak_socket.getsockname()[1])
                postgres_publish = str(postgres_socket.getsockname()[1])
        config = compose_file(work, keycloak_publish, postgres_publish)
        compose = ["docker", "compose", "-p", project, "-f", str(config)]
        try:
            subprocess.run([*compose, "up", "-d"], check=True, timeout=300)
            keycloak_port = compose_port(compose, "keycloak", "8080")
            db = compose_port(compose, "postgres", "5432")
            if keycloak_port in exclude_ports or db in exclude_ports:
                raise RuntimeError("a test container reused an excluded port")
            keycloak = f"http://localhost:{keycloak_port}"
            listener = reserved.enter_context(
                reserve_port({keycloak_port, db, *exclude_ports})
            )
            platform = f"http://localhost:{listener.getsockname()[1]}"
            prepare_fixtures(source, work, platform, keycloak, db)
            generate_keys(work, wrapping_key, ec_wrapping_key)

            def postgres_ready() -> bool:
                return (
                    subprocess.run(
                        [
                            *compose,
                            "exec",
                            "-T",
                            "postgres",
                            "pg_isready",
                            "-h",
                            "127.0.0.1",
                            "-U",
                            "postgres",
                            "-d",
                            "opentdf",
                        ],
                        timeout=5,
                        capture_output=True,
                    ).returncode
                    == 0
                )

            wait_until(postgres_ready, "Postgres")
            wait_until(
                lambda: endpoint_ready(
                    f"{keycloak}/auth/realms/master/.well-known/openid-configuration"
                ),
                "Keycloak",
            )
            service_env = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("OPENTDF_")
            }
            with (work / "platform.log").open("w+") as log:
                for setup in (
                    [
                        "provision",
                        "keycloak",
                        "--endpoint",
                        f"{keycloak}/auth",
                        "--file",
                        "keycloak.yaml",
                    ],
                    ["provision", "fixtures", "--config-file", "opentdf.yaml"],
                ):
                    subprocess.run(
                        [binary, *setup],
                        cwd=work,
                        env=service_env,
                        check=True,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=120,
                    )
                listener.close()
                platform_process = subprocess.Popen(
                    [binary, "start", "--config-file", "opentdf.yaml"],
                    cwd=work,
                    env=service_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

                def platform_ready() -> bool:
                    if platform_process.poll() is not None:
                        raise RuntimeError("OpenTDF platform exited during startup")
                    return endpoint_ready(f"{platform}/healthz")

                wait_until(platform_ready, "OpenTDF platform")
                env = {
                    **os.environ,
                    "OTDF_PLATFORM_URL": platform,
                    "OTDF_KAS_URL": platform,
                    "OTDF_KAS_KEY_ID": "r1",
                    "OTDF_TEST_KAS_EC_KEY_ID": "e1",
                    "OTDF_TEST_IDP_URL": keycloak,
                    "OTDF_TEST_ISSUER": f"{keycloak}/auth/realms/opentdf",
                    "OTDF_TEST_DB_PORT": str(db),
                    "OTDF_ATTRIBUTE": ATTRIBUTE,
                    "OTDF_TEST_ALL_OF_ATTRIBUTES": (
                        "https://example.com/attr/attr2/value/value1\n"
                        "https://example.com/attr/attr2/value/value2"
                    ),
                    "OTDF_CLIENT_ID": CLIENT_ID,
                    "OTDF_CLIENT_SECRET": CLIENT_SECRET,
                    "OTDF_ACCESS_TOKEN": fixture_token(keycloak, CLIENT_ID),
                    "OTDF_SHARED_ACCESS_TOKEN": fixture_token(keycloak, SHARED_ID),
                    "OTDF_DENIED_ACCESS_TOKEN": fixture_token(keycloak, DENIED_ID),
                }
                print(f"OpenTDF test platform ready at {platform}", flush=True)
                yield env
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            log_path = work / "platform.log"
            if log_path.exists():
                print(
                    "".join(
                        log_path.read_text(errors="replace").splitlines(keepends=True)[
                            -18:
                        ]
                    ),
                    file=sys.stderr,
                )
            raise
        finally:
            try:
                if platform_process is not None:
                    stop(platform_process)
            finally:
                subprocess.run(
                    [*compose, "down", "--volumes", "--remove-orphans"],
                    check=True,
                    timeout=60,
                )


def run_with_platform(args: argparse.Namespace, work: Path) -> int:
    source = platform_sources(args.platform_source, work)
    binary = platform_binary(source, args.platform_binary, work)
    with platform_site(source, binary, work / "site") as env:
        command = subprocess.Popen(args.command, env=env, start_new_session=True)
        try:
            result = command.wait(timeout=suite_timeout())
            return result if result >= 0 else 128 - result
        finally:
            stop(command)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform-source",
        type=Path,
        default=os.environ.get("OTDF_TEST_PLATFORM_SOURCE"),
        help=f"existing {PLATFORM_TAG} source checkout (OTDF_TEST_PLATFORM_SOURCE)",
    )
    parser.add_argument(
        "--platform-binary",
        type=Path,
        default=os.environ.get("OTDF_TEST_PLATFORM_BINARY"),
        help=f"existing {PLATFORM_TAG} service binary (OTDF_TEST_PLATFORM_BINARY)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command.pop(0)
    if not args.command:
        parser.error("provide the test command after --")
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        with tempfile.TemporaryDirectory(prefix="opentdf-stack-") as temporary:
            return run_with_platform(args, Path(temporary))
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"OpenTDF test stack failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
