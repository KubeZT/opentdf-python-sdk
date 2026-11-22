import argparse
import os
from pathlib import Path

from opentdf_sdk import AccessDenied, create_tdf, open_tdf


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create", "open", "expect-denied"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    kas = {
        "kas_url": os.environ["OTDF_KAS_URL"],
        "access_token": os.environ["OTDF_ACCESS_TOKEN"],
    }
    if args.command == "create":
        create_tdf(
            args.source,
            args.destination,
            attribute=os.environ["OTDF_ATTRIBUTE"],
            key_id=os.environ.get("OTDF_KAS_KEY_ID"),
            **kas,
        )
    elif args.command == "open":
        open_tdf(args.source, args.destination, **kas)
    else:
        try:
            open_tdf(args.source, args.destination, **kas)
        except AccessDenied:
            print("KAS denied access (permission_denied)")
        else:
            raise RuntimeError("KAS unexpectedly granted access")


if __name__ == "__main__":
    main()
