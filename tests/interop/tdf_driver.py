import argparse
import os
from pathlib import Path

from opentdf_sdk import AccessDenied, TdfError, create_tdf, open_tdf


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=["create", "create-spec", "open", "expect-denied"]
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    kas = {
        "kas_url": os.environ["OTDF_KAS_URL"],
        "access_token": os.environ["OTDF_ACCESS_TOKEN"],
    }
    manifest_kas_url = os.environ.get("OTDF_MANIFEST_KAS_URL") or None
    try:
        if args.command in {"create", "create-spec"}:
            create_tdf(
                args.source,
                args.destination,
                attribute=os.environ["OTDF_ATTRIBUTE"],
                key_id=os.environ.get("OTDF_KAS_KEY_ID"),
                profile="spec" if args.command == "create-spec" else "java",
                manifest_kas_url=manifest_kas_url,
                **kas,
            )
        else:
            open_tdf(
                args.source, args.destination, manifest_kas_url=manifest_kas_url, **kas
            )
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
