import base64
import copy
import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import pytest

from opentdf_sdk import TdfError, open_tdf
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

    if operation == "truncated-footer":
        path.write_bytes(path.read_bytes()[:-1])
    elif operation == "local-name-mismatch":
        data = bytearray(path.read_bytes())
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

    def open_case() -> None:
        open_tdf(
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
        open_case()
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
