from pathlib import Path

from opentdf_sdk import version


def test_installed_version_matches_shared_vector() -> None:
    vector = Path(__file__).resolve().parents[1] / "vectors" / "sdk-version.txt"

    assert version() + "\n" == vector.read_text(encoding="utf-8")
