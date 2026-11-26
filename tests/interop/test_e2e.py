import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("script", "start_stack"),
    [
        pytest.param("matrix.py", True, id="interoperability"),
        pytest.param("federation.py", False, id="federation"),
        pytest.param("large_payloads.py", True, id="large_payloads"),
        pytest.param("local_key.py", False, id="local_key"),
    ],
)
def test_packaged_sdks(script: str, start_stack: bool) -> None:
    here = Path(__file__).resolve().parent
    sdk = here.parents[1]
    rust_sdk = os.environ.get("RUST_SDK", str(sdk.parent / "opentdf-rust-sdk"))
    command = [
        sys.executable,
        "-B",
        str(here / script),
        "--rust-sdk",
        rust_sdk,
        str(sdk),
    ]
    if start_stack:
        command = [sys.executable, str(here / "with_platform.py"), "--", *command]
    subprocess.run(command, check=True)
