import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._json import json_object, parse_object
from ._kas import TdfError, _jwt_part, encode, utf8_json

_ASSERTION_FIELDS = {"id", "type", "scope", "statement"}
_STATEMENT_FIELDS = {"format", "value"}


@dataclass(frozen=True)
class AssertionStatement:
    """A string value and its format and optional schema identifier."""

    format: str
    schema: str
    value: str


@dataclass(frozen=True)
class AssertionConfig:
    """An assertion signed with the data key or a supplied RSA private key."""

    id: str
    kind: Literal["handling", "other"]
    scope: Literal["tdo", "payload"]
    state: Literal["encrypted", "unencrypted"]
    statement: AssertionStatement
    signing_key_pem: bytes | None = field(default=None, repr=False)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _validate_content(content: dict[str, object]) -> None:
    fields = content.keys()
    if (
        fields - {"appliesToState"} != _ASSERTION_FIELDS
        or not _nonempty(content.get("id"))
        or content.get("type") not in ("handling", "other")
        or content.get("scope") not in ("tdo", "payload")
        or content.get("appliesToState", "encrypted")
        not in ("encrypted", "unencrypted")
    ):
        raise TdfError("Invalid assertion fields")
    statement = json_object(content["statement"])
    if (
        statement.keys() - {"schema"} != _STATEMENT_FIELDS
        or not _nonempty(statement.get("format"))
        or not _nonempty(statement.get("value"))
        or not isinstance(statement.get("schema", ""), str)
    ):
        raise TdfError("Invalid assertion statement")


def _canonical(content: dict[str, object]) -> bytes:
    # The supported fields have ASCII names and string values, so sorted compact
    # UTF-8 JSON is the JSON Canonicalization Scheme representation.
    try:
        return json.dumps(
            content, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except UnicodeError as exc:
        raise TdfError("Assertion must contain valid UTF-8") from exc


def _claims(digest: bytes, tags: bytes) -> dict[str, str]:
    return {"assertionHash": digest.hex(), "assertionSig": encode(tags + digest)}


def _signing_key(pem: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TdfError("Invalid assertion signing key") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise TdfError("An assertion signing key must be RSA with at least 2048 bits")
    return key


def _verification_key(pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TdfError("Invalid assertion verification key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise TdfError(
            "An assertion verification key must be RSA with at least 2048 bits"
        )
    return key


def prepare_assertions(
    assertions: Sequence[AssertionConfig], limit: int
) -> list[tuple[dict[str, object], bytes, rsa.RSAPrivateKey | None]]:
    prepared = []
    ids: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, AssertionConfig) or not isinstance(
            assertion.statement, AssertionStatement
        ):
            raise TdfError("Invalid assertion configuration")
        statement = {
            "format": assertion.statement.format,
            "value": assertion.statement.value,
        }
        if assertion.statement.schema != "":
            statement["schema"] = assertion.statement.schema
        content: dict[str, object] = {
            "id": assertion.id,
            "type": assertion.kind,
            "scope": assertion.scope,
            "appliesToState": assertion.state,
            "statement": statement,
        }
        _validate_content(content)
        if assertion.id in ids:
            raise TdfError("Duplicate assertion ID")
        ids.add(assertion.id)
        canonical = _canonical(content)
        limit -= len(canonical)
        if limit < 0:
            raise TdfError("Manifest exceeded 4 MiB")
        pem = assertion.signing_key_pem
        prepared.append(
            (
                content,
                hashlib.sha256(canonical).digest(),
                _signing_key(pem) if pem is not None else None,
            )
        )
    return prepared


def sign_assertions(
    prepared: list[tuple[dict[str, object], bytes, rsa.RSAPrivateKey | None]],
    key: bytes,
    tags: bytes,
    limit: int,
) -> list[dict[str, object]]:
    signed = []
    for content, digest, private_key in prepared:
        alg = "HS256" if private_key is None else "RS256"
        signing_input = b".".join(
            (
                _jwt_part(utf8_json({"alg": alg})),
                _jwt_part(utf8_json(_claims(digest, tags))),
            )
        )
        signature = (
            hmac.digest(key, signing_input, "sha256")
            if private_key is None
            else private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        )
        record = {
            **content,
            "binding": {
                "method": "jws",
                "signature": b".".join((signing_input, _jwt_part(signature))).decode(
                    "ascii"
                ),
            },
        }
        limit -= len(utf8_json(record))
        if limit < 0:
            raise TdfError("Manifest exceeded 4 MiB")
        signed.append(record)
    return signed


def parse_assertions(
    assertions: object, required_ids: Sequence[str]
) -> list[tuple[str, dict[str, object], str]]:
    if not isinstance(assertions, list):
        raise TdfError("Expected an assertion list")
    if isinstance(required_ids, str) or any(not _nonempty(id_) for id_ in required_ids):
        raise TdfError("Invalid required assertion IDs")
    parsed = []
    ids = set()
    for item in assertions:
        content = json_object(item).copy()
        binding = json_object(content.pop("binding", None))
        _validate_content(content)
        id_ = content["id"]
        if id_ in ids:
            raise TdfError("Duplicate assertion ID")
        ids.add(id_)
        signature = binding.get("signature")
        if (
            binding.keys() != {"method", "signature"}
            or binding.get("method") not in ("jws", "JWS")
            or not isinstance(signature, str)
            or not signature
        ):
            raise TdfError("Invalid assertion binding")
        parsed.append((id_, content, signature))
    if not ids.issuperset(required_ids):
        raise TdfError("Required assertion is missing")
    return parsed


def _decode_jws(part: bytes) -> bytes:
    if re.fullmatch(rb"[A-Za-z0-9_-]+", part) is None:
        raise TdfError("Invalid assertion JWS encoding")
    try:
        decoded = base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))
    except ValueError as exc:
        raise TdfError("Invalid assertion JWS encoding") from exc
    if _jwt_part(decoded) != part:
        raise TdfError("Invalid assertion JWS encoding")
    return decoded


def verify_assertions(
    assertions: list[tuple[str, dict[str, object], str]],
    key: bytes,
    tags: bytes,
    verification_keys: Mapping[str, bytes],
) -> None:
    for id_, content, compact in assertions:
        parts = compact.encode("ascii").split(b".", 3)
        if len(parts) != 3:
            raise TdfError("Invalid assertion JWS")
        header_part, claims_part, signature_part = parts
        header = parse_object(_decode_jws(header_part))
        use_rsa = id_ in verification_keys
        alg = "RS256" if use_rsa else "HS256"
        if (
            header.keys() - {"typ"} != {"alg"}
            or header["alg"] != alg
            or header.get("typ", "JWT") != "JWT"
        ):
            raise TdfError("Unexpected assertion algorithm or protected headers")
        signing_input = b".".join((header_part, claims_part))
        signature = _decode_jws(signature_part)
        if not use_rsa:
            if not hmac.compare_digest(
                signature, hmac.digest(key, signing_input, "sha256")
            ):
                raise TdfError("Assertion signature verification failed")
        else:
            public_key = _verification_key(verification_keys[id_])
            try:
                public_key.verify(
                    signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
                )
            except InvalidSignature as exc:
                raise TdfError("Assertion signature verification failed") from exc
        claims = parse_object(_decode_jws(claims_part))
        if claims != _claims(hashlib.sha256(_canonical(content)).digest(), tags):
            raise TdfError("Assertion content or payload binding failed")
