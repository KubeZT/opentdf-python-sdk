import base64
import copy
import json
import struct
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import pytest

from opentdf_sdk import TdfError, open_tdf, open_tdf_with_metadata
from opentdf_sdk._kas import Kas

_CORPUS = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors/zip-profile-v1.json").read_bytes()
)
_MANIFEST_NAMES = {"java": "0.manifest.json", "spec": "manifest.json"}


def _target(manifest: dict[str, Any], pointer: str) -> tuple[Any, str]:
    *parents, field = pointer[1:].split("/")
    current: Any = manifest
    for part in parents:
        current = current[int(part) if isinstance(current, list) else part]
    return current, field


def _patch_zip(data: bytearray, case: dict[str, Any]) -> None:
    # Record offsets follow ZIP APPNOTE sections 4.3.7 and 4.3.12–4.3.16.
    footer = len(data) - 22
    cd_size, central = struct.unpack_from("<II", data, footer + 12)
    central_last = central + 46 + sum(struct.unpack_from("<3H", data, central + 28))
    (local_last,) = struct.unpack_from("<I", data, central_last + 42)
    if case.get("zip64"):
        zip32 = data[footer:]
        data[footer:] = struct.pack(
            "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 2, 2, cd_size, central
        )
        data.extend(struct.pack("<4sIQI", b"PK\x06\x07", 0, footer, 1))
        footer = len(data)
        data.extend(zip32)

    records = {
        "local": 0,
        "local-last": local_last,
        "central": central,
        "central-last": central_last,
        "footer": footer,
    }
    if case.get("zip64"):
        records |= {"zip64-record": footer - 76, "zip64-locator": footer - 20}
    for patch in case.get("zip_patches", []):
        start = records[patch["record"]] + patch["offset"]
        replacement = bytes(patch["bytes"])
        assert start + len(replacement) <= len(data)
        data[start : start + len(replacement)] = replacement


def _write_case(path: Path, profile: str, case: dict[str, Any]) -> None:
    manifest = copy.deepcopy(_CORPUS["manifests"][profile])
    manifest_name = _MANIFEST_NAMES[profile]
    payload = bytearray(base64.b64decode(_CORPUS["encrypted_payload"]))
    if "assertions" in case:
        manifest["assertions"] = [
            copy.deepcopy(_CORPUS["known_assertions"][name])
            for name in case["assertions"]
        ]
    for pointer, value in case.get("set", {}).items():
        parent, field = _target(manifest, pointer)
        parent[field] = value
    for pointer in case.get("remove", []):
        parent, field = _target(manifest, pointer)
        del parent[field]

    encoded = json.dumps(manifest).encode()
    operation = case.get("archive", "")
    payload_name = manifest["payload"]["url"] if operation == "renamed" else "0.payload"
    if operation == "short-payload":
        payload.pop()
    elif operation == "last-ciphertext-tamper":
        payload[-17] ^= 1
    elif operation == "invalid-json":
        encoded = b"{invalid"
    elif operation == "duplicate-json":
        encoded = b'{"assertions":[],' + encoded[1:]
    elif operation == "unknown-manifest":
        manifest_name = "unknown.json"

    with ZipFile(path, "w") as archive:
        archive.writestr(payload_name, payload)
        archive.writestr(manifest_name, encoded)
        if operation == "comment":
            archive.comment = b"fixture ZIP comment"
        elif operation == "extra-member":
            archive.writestr("extra.dat", b"")
        elif operation == "both-manifests":
            other = _MANIFEST_NAMES["java" if profile == "spec" else "spec"]
            archive.writestr(other, encoded)

    if (
        case.get("zip64")
        or case.get("zip_patches")
        or operation in {"truncated-footer", "local-name-mismatch"}
    ):
        data = bytearray(path.read_bytes())
        if case.get("zip64") or case.get("zip_patches"):
            _patch_zip(data, case)
        if operation == "truncated-footer":
            data.pop()
        elif operation == "local-name-mismatch":
            data[30] = ord("x")
        path.write_bytes(data)


@pytest.mark.parametrize(
    ("profile", "case"),
    [
        pytest.param(profile, case, id=f"{profile}-{case['id']}")
        for case in _CORPUS["cases"]
        for profile in case.get("profiles", _MANIFEST_NAMES)
    ],
)
def test_shared_zip_profile_conformance(
    profile: str, case: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.tdf"
    dest = tmp_path / "restored.bin"
    _write_case(source, profile, case)
    called = False

    def rewrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        nonlocal called
        called = True
        return base64.b64decode(_CORPUS["key"])

    monkeypatch.setattr(Kas, "unwrap", rewrap)
    expected = case["expect"]

    def open_case() -> str | None:
        return open_tdf_with_metadata(
            source,
            dest,
            kas_url=_CORPUS["kas_url"],
            access_token="test",
            required_assertions=case.get("required_assertions", ()),
            assertion_verification_keys={
                id_: _CORPUS["assertion_public_keys"][name].encode("ascii")
                for id_, name in case.get("assertion_keys", {}).items()
            },
        )

    if expected == "accept":
        assert open_case() == case.get("metadata")
        assert called
        assert dest.read_bytes() == base64.b64decode(_CORPUS["plaintext"])
    else:
        with pytest.raises(TdfError):
            open_case()
        assert called is (expected == "reject-after-key")
        assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(content, id=case)
        for case, content in _CORPUS["foreign_inputs"].items()
    ],
)
def test_rejects_foreign_profile_input(
    content: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.tdf"
    dest = tmp_path / "restored.bin"
    source.write_bytes(base64.b64decode(content))

    def rewrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        pytest.fail("A foreign profile input triggered KAS access")

    monkeypatch.setattr(Kas, "unwrap", rewrap)
    with pytest.raises(TdfError):
        open_tdf(source, dest, kas_url=_CORPUS["kas_url"], access_token="test")
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("profile", _MANIFEST_NAMES)
def test_rejects_every_truncated_archive_prefix(
    profile: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.tdf"
    dest = tmp_path / "restored.bin"
    case = next(case for case in _CORPUS["cases"] if case["id"] == "BASE-KNOWN-ANSWER")
    _write_case(source, profile, case)
    archive = source.read_bytes()

    def rewrap(kas: Kas, policy: str, entry: dict[str, Any]) -> bytes:
        pytest.fail(f"A truncated {profile} archive triggered KAS access")

    monkeypatch.setattr(Kas, "unwrap", rewrap)
    for length in range(len(archive)):
        source.write_bytes(archive[:length])
        try:
            open_tdf(source, dest, kas_url=_CORPUS["kas_url"], access_token="test")
        except TdfError:
            assert list(tmp_path.iterdir()) == [source], f"{profile} at byte {length}"
        else:
            pytest.fail(f"Accepted a {profile} archive truncated at byte {length}")
