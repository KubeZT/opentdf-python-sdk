import argparse
import os
from pathlib import Path

from opentdf_sdk import (
    AccessDenied,
    TdfError,
    create_tdf,
    open_tdf,
    open_tdf_with_metadata,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "create",
            "create-spec",
            "open",
            "expect-denied",
            "create-features",
            "create-spec-features",
            "open-features",
        ],
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("extra", nargs="*")
    args = parser.parse_args()
    kas = {
        "kas_url": os.environ["OTDF_KAS_URL"],
        "access_token": os.environ["OTDF_ACCESS_TOKEN"],
    }
    manifest_kas_url = os.environ.get("OTDF_MANIFEST_KAS_URL") or None
    try:
        if args.command in {"create", "create-spec"} and not args.extra:
            create_tdf(
                args.source,
                args.destination,
                attribute=os.environ["OTDF_ATTRIBUTE"],
                key_id=os.environ.get("OTDF_KAS_KEY_ID"),
                profile="spec" if args.command == "create-spec" else "java",
                manifest_kas_url=manifest_kas_url,
                **kas,
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
                manifest_kas_url=manifest_kas_url,
                **kas,
            )
        elif args.command == "open-features" and len(args.extra) == 1:
            expected = Path(args.extra[0]).read_bytes().decode("utf-8")
            metadata = open_tdf_with_metadata(
                args.source, args.destination, manifest_kas_url=manifest_kas_url, **kas
            )
            if metadata != expected:
                parser.exit(1, "Recovered metadata differs from expected metadata\n")
        elif args.command in {"open", "expect-denied"} and not args.extra:
            open_tdf(
                args.source, args.destination, manifest_kas_url=manifest_kas_url, **kas
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


if __name__ == "__main__":
    main()
