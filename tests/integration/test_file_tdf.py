import json
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from opentdf_sdk import AccessDenied, TdfError, create_tdf, open_tdf
from opentdf_sdk._kas import Kas

_KAS_URL = "http://localhost:18880"
_ATTRIBUTE = "https://example.com/attr/department/value/engineering"
_SEGMENT_SIZE = 2 * 1024 * 1024


@pytest.fixture
def local_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key: bytes | None = None

    def wrap(kas: Kas, data_key: bytes, key_id: str | None) -> tuple[str, str]:
        nonlocal key
        key = data_key
        return "r1", "A" * 342 + "=="

    def unwrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        assert key is not None
        return key

    monkeypatch.setattr(Kas, "wrap", wrap)
    monkeypatch.setattr(Kas, "unwrap", unwrap)


def _create(source: Path, dest: Path) -> None:
    create_tdf(
        source, dest, kas_url=_KAS_URL, access_token="test", attribute=_ATTRIBUTE
    )


def _open(source: Path, dest: Path) -> None:
    open_tdf(source, dest, kas_url=_KAS_URL, access_token="test")


@pytest.mark.parametrize("size", [0, 31, _SEGMENT_SIZE, _SEGMENT_SIZE + 1])
def test_roundtrip_across_segment_boundaries(
    tmp_path: Path, local_key: None, size: int
) -> None:
    source = tmp_path / "source.bin"
    container = tmp_path / "archive.tdf"
    dest = tmp_path / "recovered.bin"
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    source.write_bytes(data)
    _create(source, container)
    with ZipFile(container) as archive:
        assert archive.namelist() == ["0.payload", "0.manifest.json"]
        manifest = json.loads(archive.read("0.manifest.json"))
        assert manifest["payload"]["url"] == "0.payload"
        segments = manifest["encryptionInformation"]["integrityInformation"]["segments"]
        assert [item["segmentSize"] for item in segments] == (
            [_SEGMENT_SIZE] * (size // _SEGMENT_SIZE) + [size % _SEGMENT_SIZE]
        )
    _open(container, dest)
    assert dest.read_bytes() == data


@pytest.mark.parametrize(
    "change",
    ["ciphertext", "policy", "root", "unknown_kas", "compressed", "duplicate_json"],
)
def test_tampered_or_unsupported_container_leaves_no_output(
    tmp_path: Path, local_key: None, change: str
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"original payload")
    container = tmp_path / "archive.tdf"
    _create(source, container)
    with ZipFile(container) as archive:
        manifest = json.loads(archive.read("0.manifest.json"))
        payload = bytearray(archive.read("0.payload"))
    info = manifest["encryptionInformation"]
    if change == "ciphertext":
        payload[12] ^= 1
    elif change == "policy":
        info["keyAccess"][0]["policyBinding"]["hash"] = "A" * 86 + "=="
    elif change == "root":
        info["integrityInformation"]["rootSignature"]["sig"] = "A" * 43 + "="
    elif change == "unknown_kas":
        info["keyAccess"][0]["url"] = "https://other.invalid"
    altered = tmp_path / "altered.tdf"
    with ZipFile(altered, "w") as archive:
        archive.writestr(
            "0.payload", payload, ZIP_DEFLATED if change == "compressed" else 0
        )
        contents = json.dumps(manifest)
        if change == "duplicate_json":
            contents = '{"schemaVersion":"4.3.0",' + contents[1:]
        archive.writestr("0.manifest.json", contents)
    dest = tmp_path / "out.bin"
    with pytest.raises(TdfError):
        _open(altered, dest)
    assert not dest.exists()
    assert not list(tmp_path.glob(".tdf-*"))


def test_kas_denial_leaves_no_output(
    tmp_path: Path, local_key: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"original payload")
    container = tmp_path / "archive.tdf"
    _create(source, container)

    def deny(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        raise AccessDenied("KAS denied access")

    monkeypatch.setattr(Kas, "unwrap", deny)
    dest = tmp_path / "out.bin"
    with pytest.raises(AccessDenied):
        _open(container, dest)
    assert not dest.exists()


def test_rejects_oversized_source(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    with source.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    dest = tmp_path / "out.tdf"
    with pytest.raises(TdfError, match="64 MiB"):
        _create(source, dest)
    assert not dest.exists()


def test_extra_members_are_rejected_before_kas(tmp_path: Path) -> None:
    source = tmp_path / "too-many.tdf"
    with ZipFile(source, "w") as archive:
        archive.writestr("0.payload", b"")
        archive.writestr("0.manifest.json", b"{}")
        archive.writestr("extra", b"")
    dest = tmp_path / "out.bin"
    with pytest.raises(TdfError, match="two-entry ZIP"):
        _open(source, dest)
    assert not dest.exists()
