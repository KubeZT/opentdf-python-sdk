import hmac
import os
import re
import stat
import struct
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from io import BufferedReader
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4
from zipfile import ZIP64_LIMIT, ZIP_STORED, BadZipFile, ZipExtFile, ZipFile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._assertions import (
    AssertionConfig,
    parse_assertions,
    prepare_assertions,
    sign_assertions,
    verify_assertions,
)
from ._json import json_object as _object
from ._json import parse_object as _parse
from ._kas import KasConfig, TdfError, decode, encode, utf8_json, validate_wrapped_key

JAVA_MANIFEST = "0.manifest.json"
SPEC_MANIFEST = "manifest.json"
SCHEMA_VERSION = "4.3.0"
PAYLOAD = "0.payload"
MIB = 1024**2
SEGMENT_SIZE = 2 * MIB
NONCE_SIZE = 12
TAG_SIZE = 16
OVERHEAD = NONCE_SIZE + TAG_SIZE
AES_BLOCK_SLACK = algorithms.AES.block_size // 8 - 1
# Data descriptor and UTF-8 ZIP member names.
ZIP_MEMBER_FLAGS = 0x0808
MAX_MANIFEST = 4 * MIB
MAX_DATA_SEGMENTS = 32768
MAX_SEGMENTS = MAX_DATA_SEGMENTS + 1
MAX_SEGMENT_SIZE = 64 * MIB
MAX_PLAINTEXT = MAX_SEGMENT_SIZE * MAX_DATA_SEGMENTS
MAX_ARCHIVE = MAX_PLAINTEXT + MAX_SEGMENTS * OVERHEAD + MAX_MANIFEST + 64 * 1024


@contextmanager
def _input(
    source: str | Path, limit: int, limit_error: str
) -> Iterator[tuple[BufferedReader, int]]:
    # Nonblocking open permits checking a FIFO without waiting for a writer.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(source, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise TdfError("Expected a regular input file")
        if info.st_size > limit:
            raise TdfError(limit_error)
        with os.fdopen(descriptor, "rb", closefd=False) as file:
            yield file, info.st_size
    finally:
        os.close(descriptor)


@contextmanager
def _output(destination: str | Path) -> Iterator[IO[bytes]]:
    target = Path(destination)
    if os.path.lexists(target):
        raise FileExistsError(target)
    temp = NamedTemporaryFile(
        mode="w+b", prefix=".tdf-", dir=target.parent, delete=False
    )
    try:
        with temp:
            yield temp.file
        os.link(temp.name, target)
    finally:
        Path(temp.name).unlink(missing_ok=True)


def _mac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def _policy_hash(key: bytes, policy: str, *, spec: bool) -> bytes:
    digest = _mac(key, policy.encode("ascii"))
    return digest if spec else digest.hex().encode("ascii")


def _attribute(value: object) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 2048:
        raise TdfError("Expected a data attribute value FQN")
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
        raise TdfError("Expected a data attribute value FQN")
    return value


def _distinct_attributes(values: Iterable[object]) -> list[str]:
    attributes: list[str] = []
    seen: set[str] = set()
    size = 0
    for value in values:
        fqn = _attribute(value)
        if fqn in seen:
            raise TdfError("Duplicate policy attribute")
        size += len(fqn) + len('{"attribute":"","isDefault":false}')
        if size > MAX_MANIFEST:
            raise TdfError("Manifest exceeded 4 MiB")
        seen.add(fqn)
        attributes.append(fqn)
    if not attributes:
        raise TdfError("Expected at least one policy attribute")
    return attributes


def _encrypt_metadata(key: bytes, metadata: str | None) -> str:
    if metadata is None:
        return ""
    if not isinstance(metadata, str):
        raise TdfError("Expected metadata as UTF-8 text")
    if not metadata:
        return ""
    if len(metadata) > MAX_MANIFEST:
        raise TdfError("Manifest exceeded 4 MiB")
    try:
        plaintext = metadata.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TdfError("Expected metadata as UTF-8 text") from exc
    if len(plaintext) > MAX_MANIFEST:
        raise TdfError("Manifest exceeded 4 MiB")
    nonce = bytearray(os.urandom(NONCE_SIZE))
    # Segment counters never set the top bit of the nonce.
    nonce[0] |= 0x80
    iv = bytes(nonce)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return encode(utf8_json({"ciphertext": encode(iv + ciphertext), "iv": encode(iv)}))


def _writer_segment_plan(length: int, *, spec: bool) -> tuple[int, int]:
    size_step = MAX_DATA_SEGMENTS * MIB
    size = max(SEGMENT_SIZE, ((length + size_step - 1) // size_step) * MIB)
    full, remainder = divmod(length, size)
    count = full + (remainder > 0 or length == 0 or not spec)
    return size, count


def _select_kas(
    kas: KasConfig | None,
    url: str | None,
    token: str | None,
    manifest_origin: str | None,
) -> KasConfig:
    if kas is not None:
        if not isinstance(kas, KasConfig) or any(
            option is not None for option in (url, token, manifest_origin)
        ):
            raise TdfError("Pass either kas or the legacy KAS arguments")
        return kas
    if url is None or token is None:
        raise TdfError("Pass either kas or both kas_url and access_token")
    return KasConfig(url, token, manifest_kas_url=manifest_origin)


def create_tdf(
    source: str | Path,
    destination: str | Path,
    *,
    kas_url: str | None = None,
    access_token: str | None = None,
    kas: KasConfig | None = None,
    attribute: str | None = None,
    attributes: Sequence[str] | None = None,
    metadata: str | None = None,
    assertions: Sequence[AssertionConfig] = (),
    key_id: str | None = None,
    profile: Literal["java", "spec"] = "java",
    manifest_kas_url: str | None = None,
) -> None:
    """Encrypt a file using the selected TDF ZIP profile.

    The default matches Java SDK 0.19.1. The spec profile uses the manifest
    filename, version field, and policy HMAC encoding from OpenTDF 4.3.0.
    Pass one attribute or a sequence of distinct attributes. Nonempty metadata
    is encrypted with the same key as the payload. Assertion statements are
    stored in the manifest and signed with the data key or a supplied RSA key.
    Pass a KasConfig or the legacy kas_url and access_token arguments.
    Supply manifest_kas_url with the legacy arguments to record a different KAS
    origin in the archive. Supports plaintext files up to 2 TiB.
    """
    if profile not in ("java", "spec"):
        raise TdfError("Unknown TDF ZIP profile")
    spec = profile == "spec"
    if attribute is not None and attributes is None:
        selected = _distinct_attributes((attribute,))
    elif (
        attribute is None
        and isinstance(attributes, Sequence)
        and not isinstance(attributes, (str, bytes, bytearray))
    ):
        selected = _distinct_attributes(attributes)
    else:
        raise TdfError("Pass attribute or a sequence of attributes")
    policy = encode(
        utf8_json(
            {
                "uuid": str(uuid4()),
                "body": {
                    "dataAttributes": [
                        {"attribute": value, "isDefault": False} for value in selected
                    ],
                    "dissem": [],
                },
            }
        )
    )
    prepared = prepare_assertions(assertions, MAX_MANIFEST - len(policy))
    config = _select_kas(kas, kas_url, access_token, manifest_kas_url)
    with (
        _input(source, MAX_PLAINTEXT, "Source exceeded 2 TiB") as (plaintext, length),
        _output(destination) as output,
    ):
        segment_size, segment_count = _writer_segment_plan(length, spec=spec)
        payload_length = length + segment_count * OVERHEAD
        key = os.urandom(32)
        encrypted_metadata = _encrypt_metadata(key, metadata)
        if len(policy) + len(encrypted_metadata) > MAX_MANIFEST:
            raise TdfError("Manifest exceeded 4 MiB")
        kid, wrapped, *ephemeral = config.wrap(key, key_id)
        key_access = {
            "type": "ec-wrapped" if ephemeral else "wrapped",
            "url": config.manifest_url,
            "protocol": "kas",
            "kid": kid,
            "sid": "",
            "encryptedMetadata": encrypted_metadata,
            "schemaVersion": "1.0",
            "wrappedKey": wrapped,
            "policyBinding": {
                "alg": "HS256",
                "hash": encode(_policy_hash(key, policy, spec=spec)),
            },
        }
        if ephemeral:
            key_access["ephemeralPublicKey"] = ephemeral[0]
        segments: list[dict[str, str | int]] = []
        tags = bytearray()
        aes = algorithms.AES(key)
        plaintext_buffer = memoryview(bytearray(min(segment_size, length)))
        encrypted_buffer = memoryview(bytearray(len(plaintext_buffer) + OVERHEAD))
        with ZipFile(output, "w", compression=ZIP_STORED) as archive:
            with archive.open(
                PAYLOAD, "w", force_zip64=payload_length > ZIP64_LIMIT
            ) as payload:
                for index in range(segment_count):
                    size = min(segment_size, length - index * segment_size)
                    segment = plaintext_buffer[:size]
                    if plaintext.readinto(segment) != size:
                        raise TdfError("Source size changed while reading")
                    nonce = (index + 1).to_bytes(NONCE_SIZE, "big")
                    encryptor = Cipher(aes, modes.GCM(nonce)).encryptor()
                    encrypted_buffer[:NONCE_SIZE] = nonce
                    # The tag space also supplies the AES block slack for update_into.
                    encrypted_size = size + OVERHEAD
                    written = encryptor.update_into(
                        segment, encrypted_buffer[NONCE_SIZE:encrypted_size]
                    )
                    encryptor.finalize()
                    tag = encryptor.tag
                    encrypted_buffer[NONCE_SIZE + written : encrypted_size] = tag
                    payload.write(encrypted_buffer[:encrypted_size])
                    tags.extend(tag)
                    segments.append(
                        {
                            "hash": encode(tag),
                            "segmentSize": size,
                            "encryptedSegmentSize": encrypted_size,
                        }
                    )
                if plaintext.read(1):
                    raise TdfError("Source size changed while reading")
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
            manifest_bytes = utf8_json(
                {
                    **manifest,
                    "payload": payload_info,
                    "assertions": sign_assertions(
                        prepared,
                        key,
                        bytes(tags),
                        MAX_MANIFEST - len(policy) - len(encrypted_metadata),
                    ),
                    "encryptionInformation": {
                        "type": "split",
                        "policy": policy,
                        "keyAccess": [key_access],
                        "method": {
                            "algorithm": "AES-256-GCM",
                            "isStreamable": True,
                        },
                        "integrityInformation": {
                            "segmentHashAlg": "GMAC",
                            "segmentSizeDefault": segment_size,
                            "encryptedSegmentSizeDefault": segment_size + OVERHEAD,
                            "segments": segments,
                            "rootSignature": {
                                "alg": "HS256",
                                "sig": encode(_mac(key, bytes(tags))),
                            },
                        },
                    },
                }
            )
            if len(manifest_bytes) > MAX_MANIFEST:
                raise TdfError("Manifest exceeded 4 MiB")
            archive.writestr(SPEC_MANIFEST if spec else JAVA_MANIFEST, manifest_bytes)


def _metadata_ciphertext(value: object) -> bytes | None:
    if value == "":
        return None
    envelope = _parse(decode(value))
    if envelope.keys() != {"ciphertext", "iv"}:
        raise TdfError("Invalid encrypted metadata envelope")
    ciphertext = decode(envelope["ciphertext"])
    iv = decode(envelope["iv"], NONCE_SIZE)
    if len(ciphertext) < OVERHEAD or ciphertext[:NONCE_SIZE] != iv:
        raise TdfError("Invalid encrypted metadata framing")
    return ciphertext


def _check_directory(file: IO[bytes], length: int) -> None:
    # Bound the ZIP directory before zipfile constructs an object per entry.
    if length < 22:
        raise TdfError("Truncated ZIP")
    footer_offset = length - 22
    file.seek(footer_offset)
    signature, disk, start_disk, disk_count, count, size, offset, comment = (
        struct.unpack("<4s4H2IH", file.read(22))
    )
    if signature != b"PK\x05\x06" or disk or start_disk or comment:
        raise TdfError("Expected a single-disk ZIP without comments")

    footer_size = 22
    if footer_offset >= 20:
        file.seek(footer_offset - 20)
        locator_signature = file.read(4)
    else:
        locator_signature = b""
    if locator_signature == b"PK\x06\x07":
        footer_size = 98
        if length < footer_size:
            raise TdfError("Truncated ZIP64")
        file.seek(length - footer_size)
        record = struct.unpack("<4sQ2H2I4Q4sIQI", file.read(76))
        zip64_size, zip64_offset = record[8:10]
        if (
            record[:2] != (b"PK\x06\x06", 44)
            or record[4:8] != (0, 0, 2, 2)
            or record[10:] != (b"PK\x06\x07", 0, length - footer_size, 1)
            or disk_count not in (2, 0xFFFF)
            or count not in (2, 0xFFFF)
            or size not in (zip64_size, 0xFFFFFFFF)
            or offset not in (zip64_offset, 0xFFFFFFFF)
        ):
            raise TdfError("Invalid ZIP64 directory")
        size, offset = zip64_size, zip64_offset
    elif (disk_count, count) != (2, 2):
        raise TdfError("Expected a two-entry ZIP")
    if size > 4096 or offset + size != length - footer_size:
        raise TdfError("Invalid ZIP directory")


def _read(
    archive: ZipFile,
    output: IO[bytes],
    kas: KasConfig,
    required_assertions: Sequence[str],
    assertion_verification_keys: Mapping[str, bytes],
) -> str | None:
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
    assertions = parse_assertions(manifest.get("assertions", []), required_assertions)
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
        raise TdfError("Expected AES-256-GCM with one wrapped key")
    key_access = _object(keys[0])
    binding = _object(key_access.get("policyBinding"))
    if key_access.get("url") != kas.manifest_url:
        raise TdfError("Untrusted manifest KAS origin")
    if (
        key_access.get("type") not in ("wrapped", "ec-wrapped")
        or key_access.get("protocol") != "kas"
        or key_access.get("schemaVersion") != "1.0"
        or key_access.get("sid", "") != ""
        or not isinstance(key_access.get("kid"), str)
        or not key_access["kid"]
        or binding.get("alg") != "HS256"
    ):
        raise TdfError("Unsupported key access entry")
    metadata_ciphertext = _metadata_ciphertext(key_access.get("encryptedMetadata", ""))
    validate_wrapped_key(key_access)
    binding_hash = decode(binding.get("hash"), 32 if spec else 64)
    if not spec and not re.fullmatch(rb"[0-9a-f]{64}", binding_hash):
        raise TdfError("Invalid policy binding encoding")

    policy = info.get("policy")
    policy_json = _parse(decode(policy))
    UUID(policy_json["uuid"])
    body = _object(policy_json.get("body"))
    attributes = body.get("dataAttributes")
    if not isinstance(attributes, list) or body.get("dissem") != []:
        raise TdfError("Invalid policy body")
    attribute_values: list[object] = []
    for entry in attributes:
        attribute = _object(entry)
        if attribute.get("isDefault", False) is not False or any(
            attribute.get(field, "") != ""
            for field in ("displayName", "pubKey", "kasURL")
        ):
            raise TdfError("Unsupported policy attribute metadata")
        attribute_values.append(attribute.get("attribute"))
    _distinct_attributes(attribute_values)
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

    with cast(ZipExtFile, archive.open(payload_name)) as encrypted:
        key = kas.unwrap(policy, key_access)
        if not hmac.compare_digest(_policy_hash(key, policy, spec=spec), binding_hash):
            raise TdfError("Policy binding failed")
        tags = b"".join(tag for _, _, tag in validated_segments)
        if not hmac.compare_digest(_mac(key, tags), root_hash):
            raise TdfError("Root integrity check failed")
        verify_assertions(assertions, key, tags, assertion_verification_keys)
        metadata = None
        metadata_nonce = None
        if metadata_ciphertext is not None:
            metadata_nonce = metadata_ciphertext[:NONCE_SIZE]
            metadata = (
                AESGCM(key)
                .decrypt(
                    metadata_nonce,
                    metadata_ciphertext[NONCE_SIZE:],
                    None,
                )
                .decode("utf-8")
                or None
            )
        aes = algorithms.AES(key)
        largest_segment = max(size for size, _, _ in validated_segments)
        encrypted_buffer = memoryview(bytearray(largest_segment + OVERHEAD))
        plaintext_buffer = memoryview(bytearray(largest_segment + AES_BLOCK_SLACK))
        for _, size, tag in validated_segments:
            chunk = encrypted_buffer[:size]
            if encrypted.readinto(chunk) != size or not hmac.compare_digest(
                chunk[-TAG_SIZE:], tag
            ):
                raise TdfError("Segment framing or integrity check failed")
            nonce = chunk[:NONCE_SIZE]
            if metadata_nonce is not None and nonce == metadata_nonce:
                raise TdfError("Metadata and payload reuse a nonce")
            decryptor = Cipher(aes, modes.GCM(nonce, tag)).decryptor()
            written = decryptor.update_into(
                chunk[NONCE_SIZE:-TAG_SIZE], plaintext_buffer
            )
            decryptor.finalize()
            output.write(plaintext_buffer[:written])
        return metadata


def open_tdf(
    source: str | Path,
    destination: str | Path,
    *,
    kas_url: str | None = None,
    access_token: str | None = None,
    kas: KasConfig | None = None,
    manifest_kas_url: str | None = None,
    required_assertions: Sequence[str] = (),
    assertion_verification_keys: Mapping[str, bytes] | None = None,
) -> None:
    """Open a supported TDF ZIP profile and discard any authenticated metadata."""
    open_tdf_with_metadata(
        source,
        destination,
        kas_url=kas_url,
        access_token=access_token,
        kas=kas,
        manifest_kas_url=manifest_kas_url,
        required_assertions=required_assertions,
        assertion_verification_keys=assertion_verification_keys,
    )


def open_tdf_with_metadata(
    source: str | Path,
    destination: str | Path,
    *,
    kas_url: str | None = None,
    access_token: str | None = None,
    kas: KasConfig | None = None,
    manifest_kas_url: str | None = None,
    required_assertions: Sequence[str] = (),
    assertion_verification_keys: Mapping[str, bytes] | None = None,
) -> str | None:
    """Open a supported TDF ZIP profile and return its metadata if present.

    Pass a KasConfig or the legacy kas_url and access_token arguments. The
    key access object must match the trusted origin in the configuration.

    Present assertions must verify. Specify required assertion IDs to require
    their presence and map RS256 assertion IDs to trusted RSA public keys in PEM.
    """
    config = _select_kas(kas, kas_url, access_token, manifest_kas_url)
    verification_keys = (
        {} if assertion_verification_keys is None else assertion_verification_keys
    )
    if not isinstance(verification_keys, Mapping) or any(
        not isinstance(id_, str) or not id_ for id_ in verification_keys
    ):
        raise TdfError("Invalid assertion verification key ID")
    try:
        with (
            _input(source, MAX_ARCHIVE, "TDF exceeds the archive size limit") as (
                content,
                length,
            ),
            _output(destination) as output,
        ):
            _check_directory(content, length)
            with ZipFile(content) as archive:
                metadata = _read(
                    archive,
                    output,
                    config,
                    required_assertions,
                    verification_keys,
                )
            if os.fstat(content.fileno()).st_size != length:
                raise TdfError("TDF size changed while reading")
            return metadata
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
