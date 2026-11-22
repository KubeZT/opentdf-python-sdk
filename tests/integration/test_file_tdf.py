import base64
import hmac
import json
import struct
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opentdf_sdk import AccessDenied, TdfError, _tdf, create_tdf, open_tdf
from opentdf_sdk._kas import Kas

_KAS_URL = "http://localhost:18880"
_ATTRIBUTE = "https://example.com/attr/department/value/engineering"
_SEGMENT_SIZE = 2 * 1024 * 1024


@pytest.fixture
def local_key(monkeypatch: pytest.MonkeyPatch) -> Callable[[], bytes]:
    key: bytes | None = None

    def wrap(kas: Kas, data_key: bytes, key_id: str | None) -> tuple[str, str]:
        nonlocal key
        key = data_key
        return "r1", "A" * 342 + "=="

    def data_key() -> bytes:
        assert key is not None
        return key

    def unwrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        return data_key()

    monkeypatch.setattr(Kas, "wrap", wrap)
    monkeypatch.setattr(Kas, "unwrap", unwrap)
    return data_key


def _create(
    source: Path, dest: Path, profile: Literal["java", "spec"] = "java"
) -> None:
    create_tdf(
        source,
        dest,
        kas_url=_KAS_URL,
        access_token="test",
        attribute=_ATTRIBUTE,
        profile=profile,
    )


def _open(source: Path, dest: Path) -> None:
    open_tdf(source, dest, kas_url=_KAS_URL, access_token="test")


@pytest.mark.parametrize("profile", ["java", "spec"])
@pytest.mark.parametrize("size", [0, 31, _SEGMENT_SIZE, _SEGMENT_SIZE + 1])
def test_roundtrip_across_segment_boundaries(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    size: int,
    profile: Literal["java", "spec"],
) -> None:
    source = tmp_path / "source.bin"
    container = tmp_path / "archive.tdf"
    dest = tmp_path / "recovered.bin"
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    source.write_bytes(data)
    _create(source, container, profile)
    manifest_name = "manifest.json" if profile == "spec" else "0.manifest.json"
    with ZipFile(container) as archive:
        assert archive.namelist() == ["0.payload", manifest_name]
        manifest = json.loads(archive.read(manifest_name))
        encrypted_payload = archive.read("0.payload")
    assert manifest["payload"]["url"] == "0.payload"
    info = manifest["encryptionInformation"]
    policy_binding = info["keyAccess"][0]["policyBinding"]
    expected_hmac = hmac.digest(local_key(), info["policy"].encode("ascii"), "sha256")
    sizes = [_SEGMENT_SIZE] * (size // _SEGMENT_SIZE)
    if profile == "spec":
        assert manifest["payload"]["tdf_spec_version"] == "4.3.0"
        assert "schemaVersion" not in manifest
        if not sizes or size % _SEGMENT_SIZE:
            sizes.append(size % _SEGMENT_SIZE)
    else:
        assert manifest["schemaVersion"] == "4.3.0"
        assert "tdf_spec_version" not in manifest["payload"]
        expected_hmac = expected_hmac.hex().encode("ascii")
        sizes.append(size % _SEGMENT_SIZE)
    assert policy_binding["alg"] == "HS256"
    assert base64.b64decode(policy_binding["hash"], validate=True) == expected_hmac
    segments = info["integrityInformation"]["segments"]
    assert [item["segmentSize"] for item in segments] == sizes
    reference = AESGCM(local_key())
    expected = bytearray()
    offset = 0
    for index, segment_size in enumerate(sizes, start=1):
        nonce = index.to_bytes(12, "big")
        expected.extend(nonce)
        expected.extend(
            reference.encrypt(nonce, data[offset : offset + segment_size], None)
        )
        offset += segment_size
    assert encrypted_payload == expected
    _open(container, dest)
    assert dest.read_bytes() == data


@pytest.mark.parametrize("profile", ["java", "spec"])
@pytest.mark.parametrize(
    "change",
    ["ciphertext", "policy", "root", "unknown_kas", "compressed", "duplicate_json"],
)
def test_tampered_or_unsupported_container_leaves_no_output(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    change: str,
    profile: Literal["java", "spec"],
) -> None:
    source = tmp_path / "source.bin"
    data = b"x" * (_SEGMENT_SIZE + 1) if change == "ciphertext" else b"original payload"
    source.write_bytes(data)
    container = tmp_path / "archive.tdf"
    _create(source, container, profile)
    manifest_name = "manifest.json" if profile == "spec" else "0.manifest.json"
    with ZipFile(container) as archive:
        manifest = json.loads(archive.read(manifest_name))
        payload = bytearray(archive.read("0.payload"))
    info = manifest["encryptionInformation"]
    if change == "ciphertext":
        payload[-17] ^= 1
    elif change == "policy":
        binding = info["keyAccess"][0]["policyBinding"]
        bad_hash = bytes(32) if profile == "spec" else b"0" * 64
        binding["hash"] = base64.b64encode(bad_hash).decode("ascii")
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
            contents = '{"assertions":[],' + contents[1:]
        archive.writestr(manifest_name, contents)
    dest = tmp_path / "out.bin"
    with pytest.raises(TdfError):
        _open(altered, dest)
    assert not dest.exists()
    assert not list(tmp_path.glob(".tdf-*"))


def test_kas_denial_leaves_no_output(
    tmp_path: Path, local_key: Callable[[], bytes], monkeypatch: pytest.MonkeyPatch
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
        stream.truncate(2 * 1024**4 + 1)
    dest = tmp_path / "out.tdf"
    with pytest.raises(TdfError, match="2 TiB"):
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


@pytest.mark.parametrize(
    "payload_name", ["part-1.data", "nested/part.data", ".payload"]
)
def test_spec_payload_reference_must_be_flat_and_safe(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    monkeypatch: pytest.MonkeyPatch,
    payload_name: str,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"spec payload")
    container = tmp_path / "archive.tdf"
    _create(source, container, "spec")
    with ZipFile(container) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        payload = archive.read("0.payload")
    manifest["payload"]["url"] = payload_name
    updated = tmp_path / "updated.tdf"
    with ZipFile(updated, "w") as archive:
        archive.writestr(payload_name, payload)
        archive.writestr("manifest.json", json.dumps(manifest))

    dest = tmp_path / "restored.bin"
    if payload_name == "part-1.data":
        _open(updated, dest)
        assert dest.read_bytes() == source.read_bytes()
    else:
        monkeypatch.setattr(Kas, "unwrap", _unexpected_unwrap)
        with pytest.raises(TdfError, match="payload reference"):
            _open(updated, dest)
        assert not dest.exists()


def _unexpected_unwrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
    raise AssertionError("Malformed archive reached KAS")


@pytest.mark.parametrize(
    "change", ["both_manifests", "both_versions", "legacy_binding"]
)
def test_spec_rejects_ambiguous_profiles_before_kas(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"spec payload")
    container = tmp_path / "archive.tdf"
    _create(source, container, "spec")
    with ZipFile(container) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        payload = archive.read("0.payload")
    if change == "both_versions":
        manifest["schemaVersion"] = "4.3.0"
    elif change == "root_alias":
        manifest["tdf_spec_version"] = "4.2.0"
    elif change == "legacy_binding":
        binding = manifest["encryptionInformation"]["keyAccess"][0]["policyBinding"]
        raw = base64.b64decode(binding["hash"])
        binding["hash"] = base64.b64encode(raw.hex().encode("ascii")).decode("ascii")

    updated = tmp_path / "updated.tdf"
    with ZipFile(updated, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        if change == "both_manifests":
            archive.writestr("0.manifest.json", json.dumps(manifest))
        archive.writestr("0.payload", payload)

    monkeypatch.setattr(Kas, "unwrap", _unexpected_unwrap)
    dest = tmp_path / "restored.bin"
    with pytest.raises(TdfError):
        _open(updated, dest)
    assert not dest.exists()
    assert not list(tmp_path.glob(".tdf-*"))


@pytest.mark.parametrize("validation", ["valid", "legacy_count", "locator_offset"])
def test_streamed_zip64_directory(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    monkeypatch: pytest.MonkeyPatch,
    validation: str,
) -> None:
    # Exercise the standard ZIP64 records without allocating a multi-GiB fixture.
    monkeypatch.setattr(_tdf, "ZIP64_LIMIT", 1024)
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 1024)
    source = tmp_path / "input.bin"
    archive = tmp_path / "archive.tdf"
    output = tmp_path / "out.bin"
    source.write_bytes(bytes(range(256)) * 8)
    _create(source, archive, "spec")
    contents = bytearray(archive.read_bytes())
    assert contents[-98:-94] == b"PK\x06\x06"
    assert contents[-42:-38] == b"PK\x06\x07"
    assert struct.unpack_from("<HH", contents, len(contents) - 14) == (2, 2)

    if validation == "valid":
        _open(archive, output)
        assert output.read_bytes() == source.read_bytes()
    else:
        if validation == "legacy_count":
            struct.pack_into("<H", contents, len(contents) - 12, 3)
        else:
            struct.pack_into("<Q", contents, len(contents) - 34, 0)
        archive.write_bytes(contents)
        monkeypatch.setattr(Kas, "unwrap", _unexpected_unwrap)
        with pytest.raises(TdfError, match="Invalid ZIP64 directory"):
            _open(archive, output)
        assert not output.exists()
        assert not list(tmp_path.glob(".tdf-*"))


@pytest.mark.parametrize("replacement", [b"short", b"excessively long input"])
def test_writer_rejects_length_changes_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: bytes
) -> None:
    source = tmp_path / "input.bin"
    archive = tmp_path / "archive.tdf"
    source.write_bytes(b"original input")

    def wrap(kas: Kas, data_key: bytes, key_id: str | None) -> tuple[str, str]:
        source.write_bytes(replacement)
        return "r1", "A" * 342 + "=="

    monkeypatch.setattr(Kas, "wrap", wrap)
    with pytest.raises(TdfError, match="Source size changed while reading"):
        _create(source, archive)
    assert not archive.exists()
    assert not list(tmp_path.glob(".tdf-*"))


def test_reader_rejects_archive_growth_after_open(
    tmp_path: Path, local_key: Callable[[], bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.bin"
    archive = tmp_path / "archive.tdf"
    output = tmp_path / "out.bin"
    source.write_bytes(b"original input")
    _create(source, archive)

    def unwrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        with archive.open("ab") as file:
            file.write(b"new data")
        return local_key()

    monkeypatch.setattr(Kas, "unwrap", unwrap)
    with pytest.raises(TdfError, match="TDF size changed while reading"):
        _open(archive, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".tdf-*"))


def test_writer_keeps_destination_created_during_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.bin"
    destination = tmp_path / "archive.tdf"
    source.write_bytes(b"original input")

    def wrap(kas: Kas, data_key: bytes, key_id: str | None) -> tuple[str, str]:
        destination.write_bytes(b"another writer")
        return "r1", "A" * 342 + "=="

    monkeypatch.setattr(Kas, "wrap", wrap)
    with pytest.raises(FileExistsError):
        _create(source, destination)
    assert destination.read_bytes() == b"another writer"
    assert not list(tmp_path.glob(".tdf-*"))


@pytest.mark.parametrize("operation", [_create, _open])
def test_rejects_nonregular_input(
    tmp_path: Path, operation: Callable[[Path, Path], None]
) -> None:
    source = tmp_path / "directory"
    source.mkdir()
    destination = tmp_path / "output"
    with pytest.raises(TdfError, match="regular input file"):
        operation(source, destination)
    assert not destination.exists()


def test_inclusive_plaintext_limit_reaches_key_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.bin"
    destination = tmp_path / "archive.tdf"
    with source.open("wb") as stream:
        stream.truncate(2 * 1024**4)

    def stop_before_encrypting(
        kas: Kas, data_key: bytes, key_id: str | None
    ) -> tuple[str, str]:
        raise TdfError("Reached key access at limit")

    monkeypatch.setattr(Kas, "wrap", stop_before_encrypting)
    with pytest.raises(TdfError, match="Reached key access at limit"):
        _create(source, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".tdf-*"))


@pytest.mark.parametrize("limit", ["segment_count", "segment_size", "manifest"])
def test_reader_enforces_metadata_limits_before_kas(
    tmp_path: Path,
    local_key: Callable[[], bytes],
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"x")
    archive = tmp_path / "archive.tdf"
    _create(source, archive, "spec")
    with ZipFile(archive) as original:
        manifest = json.loads(original.read("manifest.json"))
        payload = original.read("0.payload")
    integrity = manifest["encryptionInformation"]["integrityInformation"]
    if limit == "segment_count":
        integrity["segments"] *= 32770
    elif limit == "segment_size":
        integrity["segmentSizeDefault"] = 64 * 1024**2 + 1
        integrity["encryptedSegmentSizeDefault"] = integrity["segmentSizeDefault"] + 28
    manifest_bytes = json.dumps(manifest).encode()
    if limit == "manifest":
        manifest_bytes = manifest_bytes.ljust(4 * 1024**2 + 1, b" ")
    with ZipFile(archive, "w") as changed:
        changed.writestr("0.payload", payload)
        changed.writestr("manifest.json", manifest_bytes)

    output = tmp_path / "out.bin"
    monkeypatch.setattr(Kas, "unwrap", _unexpected_unwrap)
    with pytest.raises(TdfError, match="4 MiB|segment or root integrity"):
        _open(archive, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".tdf-*"))


def test_oversized_archive_is_rejected_before_zip_parsing(tmp_path: Path) -> None:
    archive = tmp_path / "oversized.tdf"
    output = tmp_path / "out.bin"
    with archive.open("wb") as file:
        file.truncate(2 * 1024**4 + 32769 * 28 + 4 * 1024**2 + 64 * 1024 + 1)
    with pytest.raises(TdfError, match="archive size limit"):
        _open(archive, output)
    assert not output.exists()


@pytest.mark.parametrize(
    ("length", "size", "java_count", "spec_count"),
    [
        (0, 2 * 1024**2, 1, 1),
        (64 * 1024**3 + 1, 3 * 1024**2, 21846, 21846),
        (256 * 1024**3, 8 * 1024**2, 32769, 32768),
        (2 * 1024**4, 64 * 1024**2, 32769, 32768),
    ],
)
def test_adaptive_segment_plan(
    length: int, size: int, java_count: int, spec_count: int
) -> None:
    assert _tdf._writer_segment_plan(length, spec=False) == (size, java_count)
    assert _tdf._writer_segment_plan(length, spec=True) == (size, spec_count)


@pytest.mark.parametrize("operation", [_create, _open])
def test_rejects_dangling_destination_before_file_io(
    tmp_path: Path, operation: Callable[[Path, Path], None]
) -> None:
    source = tmp_path / "input"
    destination = tmp_path / "destination"
    missing = tmp_path / "missing"
    source.write_bytes(b"file bytes")
    destination.symlink_to(missing)

    with pytest.raises(FileExistsError):
        operation(source, destination)
    assert destination.is_symlink()
    assert destination.readlink() == missing
    assert not missing.exists()
    assert not list(tmp_path.glob(".tdf-*"))
