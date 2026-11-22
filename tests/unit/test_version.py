from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from opentdf_sdk import version


def test_missing_distribution_metadata_raises() -> None:
    with (
        patch(
            "importlib.metadata.version",
            side_effect=metadata.PackageNotFoundError("opentdf-python-sdk"),
        ),
        pytest.raises(metadata.PackageNotFoundError),
    ):
        version()


@settings(max_examples=30, derandomize=True)
@given(
    major=st.integers(min_value=0, max_value=1000),
    minor=st.integers(min_value=0, max_value=1000),
    patch_version=st.integers(min_value=0, max_value=1000),
)
def test_version_tracks_installed_metadata(
    major: int, minor: int, patch_version: int
) -> None:
    expected = f"{major}.{minor}.{patch_version}"

    with TemporaryDirectory() as directory, pytest.MonkeyPatch.context() as monkeypatch:
        dist_info = Path(directory) / f"opentdf_python_sdk-{expected}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.4\nName: opentdf-python-sdk\nVersion: {expected}\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(directory)

        assert version() == expected
