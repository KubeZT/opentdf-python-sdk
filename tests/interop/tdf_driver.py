import argparse
import os
import sys
from pathlib import Path

from opentdf_sdk import (
    AccessDenied,
    AssertionConfig,
    AssertionStatement,
    KasConfig,
    TdfError,
    create_tdf,
    open_tdf,
    open_tdf_with_metadata,
    version,
)


def main() -> None:
    if sys.argv[1:] == ["version"]:
        print(version())
        return
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "create",
            "create-spec",
            "create-p256",
            "create-spec-p256",
            "open-p256",
            "open",
            "expect-denied",
            "create-features",
            "create-spec-features",
            "open-features",
            "create-assertions",
            "create-spec-assertions",
            "open-assertions",
        ],
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("extra", nargs="*")
    args = parser.parse_args()
    try:
        kas = kas_config()
        if origin := os.environ.get("OTDF_MANIFEST_KAS_URL"):
            kas = kas.with_manifest_origin(origin)
        p256 = args.command.endswith("-p256")
        if p256:
            kas = kas.with_key_algorithm("ec:secp256r1")
        if (
            args.command in {"create", "create-spec", "create-p256", "create-spec-p256"}
            and not args.extra
        ):
            create_tdf(
                args.source,
                args.destination,
                attribute=os.environ["OTDF_ATTRIBUTE"],
                key_id=os.environ.get(
                    "OTDF_TEST_KAS_EC_KEY_ID" if p256 else "OTDF_KAS_KEY_ID"
                ),
                profile="spec" if args.command.startswith("create-spec") else "java",
                kas=kas,
            )
        elif args.command in {"create-features", "create-spec-features"} and args.extra:
            metadata, *attributes = args.extra
            create_tdf(
                args.source,
                args.destination,
                attributes=attributes,
                metadata=Path(metadata).read_bytes().decode("utf-8"),
                key_id=os.environ.get("OTDF_KAS_KEY_ID"),
                profile="spec" if args.command == "create-spec-features" else "java",
                kas=kas,
            )
        elif args.command == "open-features" and len(args.extra) == 1:
            expected = Path(args.extra[0]).read_bytes().decode("utf-8")
            metadata = open_tdf_with_metadata(
                args.source,
                args.destination,
                kas=kas,
            )
            if metadata != expected:
                parser.exit(1, "Recovered metadata differs from expected metadata\n")
        elif (
            args.command in {"create-assertions", "create-spec-assertions"}
            and len(args.extra) == 1
        ):
            create_tdf(
                args.source,
                args.destination,
                attribute=os.environ["OTDF_ATTRIBUTE"],
                profile="spec" if args.command == "create-spec-assertions" else "java",
                key_id=os.environ.get("OTDF_KAS_KEY_ID"),
                assertions=[
                    AssertionConfig(
                        id="tdf-binding",
                        kind="handling",
                        scope="payload",
                        state="unencrypted",
                        statement=AssertionStatement(
                            "text/plain", "urn:opentdf:test:assertion", "tdf assertion"
                        ),
                    ),
                    AssertionConfig(
                        id="publisher",
                        kind="other",
                        scope="payload",
                        state="unencrypted",
                        statement=AssertionStatement(
                            "text/plain",
                            "urn:opentdf:test:assertion",
                            "publisher assertion",
                        ),
                        signing_key_pem=Path(args.extra[0]).read_bytes(),
                    ),
                ],
                kas=kas,
            )
        elif args.command == "open-assertions" and len(args.extra) == 1:
            open_tdf(
                args.source,
                args.destination,
                required_assertions=("tdf-binding", "publisher"),
                assertion_verification_keys={
                    "publisher": Path(args.extra[0]).read_bytes()
                },
                kas=kas,
            )
        elif args.command in {"open", "open-p256", "expect-denied"} and not args.extra:
            open_tdf(
                args.source,
                args.destination,
                kas=kas,
            )
        else:
            parser.error("invalid arguments for command")
    except AccessDenied as error:
        if args.command != "expect-denied":
            parser.exit(1, f"TDF error: {error}\n")
        print("KAS denied access (permission_denied)")
    except TdfError as error:
        parser.exit(1, f"TDF error: {error}\n")
    else:
        if args.command == "expect-denied":
            parser.exit(1, "KAS unexpectedly granted access\n")


def kas_config() -> KasConfig:
    mode = os.environ.get("OTDF_TEST_AUTH_MODE", "")
    if mode in ("", "bearer"):
        return KasConfig(os.environ["OTDF_KAS_URL"], os.environ["OTDF_ACCESS_TOKEN"])
    if mode == "discover":
        return KasConfig.discover(
            os.environ["OTDF_PLATFORM_URL"], os.environ["OTDF_ACCESS_TOKEN"]
        )
    if mode in ("client-credentials", "discover-client-credentials"):
        issuer = os.environ["OTDF_TEST_ISSUER"]
        client_id = os.environ["OTDF_CLIENT_ID"]
        client_secret = os.environ["OTDF_CLIENT_SECRET"]
        if mode == "client-credentials":
            return KasConfig.from_client_credentials(
                os.environ["OTDF_KAS_URL"], issuer, client_id, client_secret
            )
        return KasConfig.discover_with_client_credentials(
            os.environ["OTDF_PLATFORM_URL"], issuer, client_id, client_secret
        )
    raise TdfError("Invalid test authentication mode")


if __name__ == "__main__":
    main()
