import base64
import hmac
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from opentdf_sdk import AccessDenied, TdfError, create_tdf, open_tdf
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
