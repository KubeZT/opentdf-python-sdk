import hmac
import json
import os
import re
import stat
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4
from zipfile import ZIP_STORED, BadZipFile, ZipFile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._kas import Kas, TdfError, decode, encode, utf8_json

JAVA_MANIFEST = "0.manifest.json"
SPEC_MANIFEST = "manifest.json"
SCHEMA_VERSION = "4.3.0"
PAYLOAD = "0.payload"
SEGMENT_SIZE = 2 * 1024 * 1024
OVERHEAD = 28
# Data descriptor and UTF-8 ZIP member names.
ZIP_MEMBER_FLAGS = 0x0808
MAX_PLAINTEXT = 64 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_SEGMENTS = 1024
MAX_SEGMENT_SIZE = 2 * SEGMENT_SIZE
MAX_ARCHIVE = MAX_PLAINTEXT + MAX_SEGMENTS * OVERHEAD + MAX_MANIFEST + 64 * 1024


@contextmanager
def _output(destination: str | Path) -> Iterator[IO[bytes]]:
    target = Path(destination)
    if target.exists():
        raise FileExistsError(target)
    with NamedTemporaryFile(
        mode="w+b", prefix=".tdf-", dir=target.parent, delete=False
    ) as temp:
        try:
            yield temp.file
            temp.close()
            os.link(temp.name, target)
        finally:
            Path(temp.name).unlink(missing_ok=True)


def _mac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def _policy_hash(key: bytes, policy: str, *, spec: bool) -> bytes:
    digest = _mac(key, policy.encode("ascii"))
    return digest if spec else digest.hex().encode("ascii")


def _attribute(value: str) -> None:
    if not isinstance(value, str) or not value.isascii() or len(value) > 2048:
        raise TdfError("Expected one data attribute value FQN")
    try:
        uri = urlsplit(value)
    except ValueError as exc:
        raise TdfError("Invalid data attribute value FQN") from exc
    pieces = uri.path.split("/")
    if (
        uri.scheme != "https"
        or not uri.hostname
        or uri.username is not None
        or "?" in value
        or "#" in value
        or any(c.isspace() for c in value)
        or len(pieces) != 5
        or pieces[1] != "attr"
        or pieces[3] != "value"
        or not pieces[2]
        or not pieces[4]
    ):
        raise TdfError("Expected one data attribute value FQN")


def create_tdf(
    source: str | Path,
    destination: str | Path,
    *,
    kas_url: str,
    access_token: str,
    attribute: str,
    key_id: str | None = None,
    profile: Literal["java", "spec"] = "java",
) -> None:
    """Encrypt a file using the selected TDF ZIP profile.

    The default matches Java SDK 0.19.1. The spec profile uses the manifest
    filename, version field, and policy HMAC encoding from OpenTDF 4.3.0.
    """
    if profile not in ("java", "spec"):
        raise TdfError("Unknown TDF ZIP profile")
    spec = profile == "spec"
    _attribute(attribute)
    kas = Kas(kas_url, access_token)
    with Path(source).open("rb") as plaintext, _output(destination) as output:
        source_info = os.fstat(plaintext.fileno())
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > MAX_PLAINTEXT:
            raise TdfError("Source must be a regular file no larger than 64 MiB")
        key = AESGCM.generate_key(bit_length=256)
        kid, wrapped = kas.wrap(key, key_id)
        segments: list[dict[str, str | int]] = []
        tags = bytearray()
        cipher = AESGCM(key)
        total = 0
        with ZipFile(output, "w", compression=ZIP_STORED) as archive:
            with archive.open(PAYLOAD, "w") as payload:
                while True:
                    segment = plaintext.read(SEGMENT_SIZE)
                    if spec and not segment and segments:
                        break
                    total += len(segment)
                    if total > MAX_PLAINTEXT:
                        raise TdfError("Source exceeded 64 MiB")
                    nonce = (len(segments) + 1).to_bytes(12, "big")
                    encrypted = nonce + cipher.encrypt(nonce, segment, None)
                    payload.write(encrypted)
                    tag = encrypted[-16:]
                    tags.extend(tag)
                    segments.append(
                        {
                            "hash": encode(tag),
                            "segmentSize": len(segment),
                            "encryptedSegmentSize": len(encrypted),
                        }
                    )
                    if len(segment) < SEGMENT_SIZE:
                        break
            policy = encode(
                utf8_json(
                    {
                        "uuid": str(uuid4()),
                        "body": {
                            "dataAttributes": [
                                {"attribute": attribute, "isDefault": False}
                            ],
                            "dissem": [],
                        },
                    }
                )
            )
            payload_info: dict[str, str | bool] = {
                "type": "reference",
                "url": PAYLOAD,
                "protocol": "zip",
                "mimeType": "application/octet-stream",
                "isEncrypted": True,
            }
            manifest: dict[str, object] = {}
            if spec:
                payload_info["tdf_spec_version"] = SCHEMA_VERSION
            else:
                manifest["schemaVersion"] = SCHEMA_VERSION
            archive.writestr(
                SPEC_MANIFEST if spec else JAVA_MANIFEST,
                utf8_json(
                    {
                        **manifest,
                        "payload": payload_info,
                        "assertions": [],
                        "encryptionInformation": {
                            "type": "split",
                            "policy": policy,
                            "keyAccess": [
                                {
                                    "type": "wrapped",
                                    "url": kas.url,
                                    "protocol": "kas",
                                    "kid": kid,
                                    "sid": "",
                                    "encryptedMetadata": "",
                                    "schemaVersion": "1.0",
                                    "wrappedKey": wrapped,
                                    "policyBinding": {
                                        "alg": "HS256",
                                        "hash": encode(
                                            _policy_hash(key, policy, spec=spec)
                                        ),
                                    },
                                }
                            ],
                            "method": {
                                "algorithm": "AES-256-GCM",
                                "isStreamable": True,
                            },
                            "integrityInformation": {
                                "segmentHashAlg": "GMAC",
                                "segmentSizeDefault": SEGMENT_SIZE,
                                "encryptedSegmentSizeDefault": SEGMENT_SIZE + OVERHEAD,
                                "segments": segments,
                                "rootSignature": {
                                    "alg": "HS256",
                                    "sig": encode(_mac(key, bytes(tags))),
                                },
                            },
                        },
                    }
                ),
            )


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TdfError("Expected a JSON object")
    return value


def _unique_object(entries: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, part in entries:
        if key in value:
            raise TdfError("Duplicate JSON field")
        value[key] = part
    return value


def _reject_constant(value: str) -> None:
    raise TdfError("Invalid JSON number")


def _parse(data: bytes) -> dict[str, Any]:
    return _object(
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    )


def _check_directory(file: IO[bytes], length: int) -> None:
    # Bound the ZIP directory before zipfile constructs an object per entry.
    if length < 22:
        raise TdfError("Truncated ZIP")
    file.seek(-22, os.SEEK_END)
    signature, disk, start_disk, disk_count, count, size, offset, comment = (
        struct.unpack("<4s4H2IH", file.read(22))
    )
    if signature != b"PK\x05\x06" or disk or start_disk or comment:
        raise TdfError("Expected a single-disk ZIP without comments")
    footer_size = 22
    if (disk_count, count, size, offset) == (0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF):
        footer_size = 98
        if length < footer_size:
            raise TdfError("Truncated ZIP64")
        file.seek(-footer_size, os.SEEK_END)
        record = struct.unpack("<4sQ2H2I4Q4sIQI", file.read(76))
        if (
            record[:2] != (b"PK\x06\x06", 44)
            or record[4:8] != (0, 0, 2, 2)
            or record[10:] != (b"PK\x06\x07", 0, length - footer_size, 1)
        ):
            raise TdfError("Invalid ZIP64 directory")
        size, offset = record[8:10]
    elif (disk_count, count) != (2, 2):
        raise TdfError("Expected a two-entry ZIP")
    if size > 4096 or offset + size != length - footer_size:
        raise TdfError("Invalid ZIP directory")


def _read(archive: ZipFile, output: IO[bytes], kas: Kas) -> None:
    entries = archive.infolist()
    names = {info.filename for info in entries}
    spec = SPEC_MANIFEST in names
    if len(entries) != 2 or len(names) != 2 or spec == (JAVA_MANIFEST in names):
        raise TdfError("Expected one payload and exactly one supported manifest")
    if any(
        info.compress_type != ZIP_STORED
        or info.compress_size != info.file_size
        or info.orig_filename != info.filename
        or info.flag_bits & ~ZIP_MEMBER_FLAGS
        for info in entries
    ):
        raise TdfError("Expected uncompressed ZIP members")
    if not any(info.header_offset == 0 for info in entries):
        raise TdfError("Expected ZIP header at the start of the archive")
    manifest_name = SPEC_MANIFEST if spec else JAVA_MANIFEST
    manifest_entry = archive.getinfo(manifest_name)
    if manifest_entry.file_size > MAX_MANIFEST:
        raise TdfError("Manifest exceeded 4 MiB")
    manifest = _parse(archive.read(manifest_entry))
    payload = _object(manifest.get("payload"))
    if spec:
        version_matches = (
            payload.get("tdf_spec_version") == SCHEMA_VERSION
            and "schemaVersion" not in manifest
        )
    else:
        version_matches = (
            manifest.get("schemaVersion") == SCHEMA_VERSION
            and "tdf_spec_version" not in payload
        )
    payload_name = payload.get("url")
    if (
        not version_matches
        or "tdf_spec_version" in manifest
        or manifest.get("assertions", []) != []
        or payload.get("type") != "reference"
        or payload.get("protocol") != "zip"
        or payload.get("isEncrypted") is not True
        or not isinstance(payload_name, str)
        or payload_name == manifest_name
        or payload_name not in names
        or not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}", payload_name)
        or (not spec and payload_name != PAYLOAD)
    ):
        raise TdfError("Unsupported TDF manifest or payload reference")
    info = _object(manifest.get("encryptionInformation"))
    method = _object(info.get("method"))
    keys = info.get("keyAccess")
    if (
        info.get("type") != "split"
        or method.get("algorithm") != "AES-256-GCM"
        or method.get("isStreamable") is not True
        or method.get("iv", "") != ""
        or not isinstance(keys, list)
        or len(keys) != 1
    ):
        raise TdfError("Expected AES-256-GCM with one RSA-wrapped key")
    key_access = _object(keys[0])
    binding = _object(key_access.get("policyBinding"))
    if (
        key_access.get("type") != "wrapped"
        or key_access.get("protocol") != "kas"
        or key_access.get("schemaVersion") != "1.0"
        or key_access.get("sid", "") != ""
        or key_access.get("encryptedMetadata", "") != ""
        or key_access.get("url") != kas.url
        or not isinstance(key_access.get("kid"), str)
        or not key_access["kid"]
        or binding.get("alg") != "HS256"
    ):
        raise TdfError("Unsupported key access entry or untrusted KAS")
    decode(key_access.get("wrappedKey"), 256)
    binding_hash = decode(binding.get("hash"), 32 if spec else 64)
    if not spec and not re.fullmatch(rb"[0-9a-f]{64}", binding_hash):
        raise TdfError("Invalid policy binding encoding")

    policy = info.get("policy")
    policy_json = _parse(decode(policy))
    UUID(policy_json["uuid"])
    body = _object(policy_json.get("body"))
    attributes = body.get("dataAttributes")
    if (
        not isinstance(attributes, list)
        or len(attributes) != 1
        or body.get("dissem") != []
    ):
        raise TdfError("Expected one policy attribute")
    attribute = _object(attributes[0])
    if attribute.get("isDefault", False) is not False or any(
        attribute.get(field, "") != "" for field in ("displayName", "pubKey", "kasURL")
    ):
        raise TdfError("Unsupported policy attribute metadata")
    _attribute(attribute["attribute"])
    assert isinstance(policy, str)

    integrity = _object(info.get("integrityInformation"))
    root = _object(integrity.get("rootSignature"))
    segments = integrity.get("segments")
    segment_default = integrity.get("segmentSizeDefault")
    encrypted_default = integrity.get("encryptedSegmentSizeDefault")
    if (
        integrity.get("segmentHashAlg") != "GMAC"
        or root.get("alg") != "HS256"
        or not isinstance(segments, list)
        or not 1 <= len(segments) <= MAX_SEGMENTS
        or type(segment_default) is not int
        or not 1 <= segment_default <= MAX_SEGMENT_SIZE
        or type(encrypted_default) is not int
        or encrypted_default != segment_default + OVERHEAD
    ):
        raise TdfError("Unsupported segment or root integrity metadata")
    root_hash = decode(root.get("sig"), 32)
    validated_segments = []
    for index, entry in enumerate(segments):
        segment = _object(entry)
        size = segment.get("segmentSize", segment_default)
        encrypted_size = segment.get("encryptedSegmentSize", encrypted_default)
        if (
            type(size) is not int
            or type(encrypted_size) is not int
            or not 0 <= size <= segment_default
            or (index < len(segments) - 1 and size != segment_default)
            or encrypted_size != size + OVERHEAD
        ):
            raise TdfError("Invalid segment size")
        validated_segments.append(
            (size, encrypted_size, decode(segment.get("hash"), 16))
        )
    if (
        sum(size for size, _, _ in validated_segments) > MAX_PLAINTEXT
        or sum(size for _, size, _ in validated_segments)
        != archive.getinfo(payload_name).file_size
    ):
        raise TdfError("Invalid payload size")

    with archive.open(payload_name) as encrypted:
        key = kas.unwrap(policy, key_access)
        if not hmac.compare_digest(_policy_hash(key, policy, spec=spec), binding_hash):
            raise TdfError("Policy binding failed")
        if not hmac.compare_digest(
            _mac(key, b"".join(tag for _, _, tag in validated_segments)), root_hash
        ):
            raise TdfError("Root integrity check failed")
        cipher = AESGCM(key)
        for _, size, tag in validated_segments:
            chunk = encrypted.read(size)
            if len(chunk) != size or not hmac.compare_digest(chunk[-16:], tag):
                raise TdfError("Segment framing or integrity check failed")
            output.write(cipher.decrypt(chunk[:12], chunk[12:], None))


def open_tdf(
    source: str | Path,
    destination: str | Path,
    *,
    kas_url: str,
    access_token: str,
) -> None:
    """Open a supported TDF ZIP profile after KAS authorization."""
    kas = Kas(kas_url, access_token)
    try:
        with Path(source).open("rb") as content, _output(destination) as output:
            info = os.fstat(content.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
                raise TdfError("TDF exceeds the archive size limit")
            _check_directory(content, info.st_size)
            with ZipFile(content) as archive:
                _read(archive, output, kas)
    except TdfError:
        raise
    except (
        BadZipFile,
        InvalidTag,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        struct.error,
    ) as exc:
        raise TdfError("Invalid or unauthenticated TDF") from exc
