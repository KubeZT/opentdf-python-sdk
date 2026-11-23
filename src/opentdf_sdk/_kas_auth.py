import base64
import http.client
import math
import re
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import SplitResult, quote_plus, urlsplit

from ._errors import TdfError
from ._json import parse_object

_RESPONSE_LIMIT = 128 * 1024


def split_url(
    url: str,
    *,
    allow_path: bool = False,
    allow_query: bool = False,
    purpose: str = "HTTP(S) URL",
) -> SplitResult:
    disallowed = "#\\" if allow_query else "?#\\"
    if not isinstance(url, str) or any(
        not 0x21 <= ord(c) <= 0x7E or c in disallowed for c in url
    ):
        raise TdfError(f"Invalid {purpose}")
    try:
        parsed = urlsplit(url)
        parsed.port  # Validate an explicit port.
    except ValueError:
        raise TdfError(f"Invalid {purpose}") from None
    host = parsed.hostname
    authority = parsed.netloc
    ipv6_suffix = authority.rpartition("]")[2] if authority.startswith("[") else ""
    if (
        not host
        or parsed.username is not None
        or (not allow_path and parsed.path not in {"", "/"})
        or authority.endswith(":")
        or ("[" in authority and not authority.startswith("["))
        or (ipv6_suffix and not ipv6_suffix.startswith(":"))
        or parsed.scheme not in {"https", "http"}
    ):
        raise TdfError(f"Invalid {purpose}")
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise TdfError(f"{purpose} uses HTTP outside loopback")
    return parsed


def _origin(url: SplitResult) -> tuple[str, str | None, int]:
    port = (443 if url.scheme == "https" else 80) if url.port is None else url.port
    return url.scheme, url.hostname, port


def bearer_token(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=\-]+", value):
        raise TdfError("Invalid bearer token")
    return value


def request_json(
    endpoint: SplitResult,
    method: str,
    path: str,
    context: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    connection_class = (
        http.client.HTTPSConnection
        if endpoint.scheme == "https"
        else http.client.HTTPConnection
    )
    assert endpoint.hostname is not None
    connection = connection_class(endpoint.hostname, endpoint.port, timeout=10)
    try:
        connection.request(method, path, body, headers or {})
        with connection.getresponse() as response:
            status = response.status
            length = response.length
            payload = response.read(_RESPONSE_LIMIT + 1)
    except (OSError, http.client.HTTPException):
        raise TdfError(f"{context} could not be reached") from None
    finally:
        connection.close()
    if len(payload) > _RESPONSE_LIMIT:
        raise TdfError(f"{context} response exceeded the size limit")
    if isinstance(length, int) and len(payload) != length:
        raise TdfError(f"Incomplete {context} response")
    try:
        return status, parse_object(payload)
    except (ValueError, RecursionError):
        raise TdfError(f"{context} returned HTTP {status} with invalid JSON") from None


def discover_platform(platform: str) -> tuple[str, object]:
    endpoint = split_url(platform)
    context = "Platform discovery"
    status, result = request_json(
        endpoint, "GET", "/.well-known/opentdf-configuration", context
    )
    if status != 200:
        raise TdfError(f"{context} returned HTTP {status}")
    base_key = result.get("base_key")
    if base_key is None or base_key == {}:
        return platform, result.get("platform_issuer")
    if not isinstance(base_key, dict):
        raise TdfError("Invalid advertised base key")
    kas: object = base_key.get("kas_uri", base_key.get("kasUri"))
    if not isinstance(kas, str) or {"kas_uri", "kasUri"} <= base_key.keys():
        raise TdfError("Invalid advertised KAS origin")
    if endpoint.scheme == "https" and split_url(kas).scheme != "https":
        raise TdfError("HTTPS platform advertised a plaintext KAS")
    return kas, result.get("platform_issuer")


class ClientCredentials:
    def __init__(self, issuer: str, client_id: str, client_secret: str) -> None:
        issuer_url = split_url(issuer, allow_path=True)
        if not all(
            isinstance(value, str) and value for value in (client_id, client_secret)
        ):
            raise TdfError("OAuth client ID and secret are required")
        self._issuer = issuer
        self._issuer_url = issuer_url
        credentials = f"{quote_plus(client_id)}:{quote_plus(client_secret)}"
        self._authorization = f"Basic {base64.b64encode(credentials.encode()).decode()}"
        self._endpoint: SplitResult | None = None
        self._token = ""
        self._expires_at = 0.0
        self._lock = Lock()

    def _discover_endpoint(self) -> SplitResult:
        path = (
            self._issuer_url.path.removesuffix("/")
            + "/.well-known/openid-configuration"
        )
        status, result = request_json(self._issuer_url, "GET", path, "OIDC discovery")
        if status != 200:
            raise TdfError(f"OIDC discovery returned HTTP {status}")
        if result.get("issuer") != self._issuer:
            raise TdfError("OIDC issuer does not match the configured issuer")
        methods = result.get("token_endpoint_auth_methods_supported")
        if "token_endpoint_auth_methods_supported" in result and (
            not isinstance(methods, list)
            or any(not isinstance(method, str) for method in methods)
            or "client_secret_basic" not in methods
        ):
            raise TdfError("OIDC token endpoint does not support client_secret_basic")
        endpoint = result.get("token_endpoint")
        if not isinstance(endpoint, str):
            raise TdfError("OIDC discovery did not return a token endpoint")
        parsed = split_url(endpoint, allow_path=True, allow_query=True)
        if _origin(parsed) != _origin(self._issuer_url):
            raise TdfError("OIDC token endpoint must use the configured issuer origin")
        return parsed

    def token(self) -> str:
        with self._lock:
            if monotonic() < self._expires_at:
                return self._token
            if self._endpoint is None:
                self._endpoint = self._discover_endpoint()
            now = monotonic()
            target = self._endpoint.path or "/"
            if self._endpoint.query:
                target += f"?{self._endpoint.query}"
            status, result = request_json(
                self._endpoint,
                "POST",
                target,
                "OAuth client credentials",
                body=b"grant_type=client_credentials",
                headers={
                    "Authorization": self._authorization,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            if status != 200:
                raise TdfError(f"OAuth client credentials returned HTTP {status}")
            kind = result.get("token_type")
            if not isinstance(kind, str) or kind.lower() != "bearer":
                raise TdfError("OAuth response did not contain a bearer token")
            token = bearer_token(result.get("access_token"))
            if "expires_in" in result:
                expires = result["expires_in"]
                if type(expires) not in (int, float):
                    raise TdfError("Invalid OAuth token lifetime")
                try:
                    lifespan = float(expires)
                except OverflowError:
                    raise TdfError("Invalid OAuth token lifetime") from None
                if not math.isfinite(lifespan) or lifespan <= 0:
                    raise TdfError("Invalid OAuth token lifetime")
                self._expires_at = now + lifespan - min(lifespan * 0.1, 30)
                self._token = token
            return token
