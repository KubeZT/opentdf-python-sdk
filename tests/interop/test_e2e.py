import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.e2e
def test_packaged_sdk_interoperability() -> None:
    here = Path(__file__).resolve().parent
    sdk = here.parents[1]
    rust_sdk = os.environ.get("RUST_SDK", str(sdk.parent / "opentdf-rust-sdk"))
    subprocess.run(
        [
            sys.executable,
            str(here / "with_platform.py"),
            "--",
            sys.executable,
            "-B",
            str(here / "matrix.py"),
            "--rust-sdk",
            rust_sdk,
            str(sdk),
        ],
        check=True,
    )
