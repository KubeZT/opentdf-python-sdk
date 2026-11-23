import base64
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from zipfile import ZipFile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from opentdf_sdk import (
    AccessDenied,
    KasConfig,
    TdfError,
    _kas_auth,
    create_tdf,
    open_tdf,
)

_TOKEN = "loopback-kas-test-token"
_ATTRIBUTE = "https://example.com/attr/department/value/engineering"
_PAYLOAD = b"actual transport test payload"
_LIMIT = 128 * 1024
_OAEP = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    authorization: str | None
    body: bytes


@dataclass(frozen=True)
class Reply:
    status: int = 200
    body: bytes = b"{}"
    headers: tuple[tuple[str, str], ...] = ()


@contextmanager
def serve(reply: Callable[[Request], Reply]) -> Iterator[tuple[str, list[Request]]]:
    requests: list[Request] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.respond()

        def do_POST(self) -> None:
            self.respond()

        def respond(self) -> None:
            request = Request(
                self.command,
                self.path,
                self.headers.get("Authorization"),
                self.rfile.read(int(self.headers.get("Content-Length", "0"))),
            )
            requests.append(request)
            result = reply(request)
            self.send_response(result.status)
            if not any(name.lower() == "content-length" for name, _ in result.headers):
                self.send_header("Content-Length", str(len(result.body)))
            self.send_header("Content-Type", "application/json")
            for name, value in result.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(result.body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        runner = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        runner.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            runner.join()


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_reply(private: rsa.RSAPrivateKey) -> dict[str, str]:
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"kid": "r1", "publicKey": pem.decode("ascii")}


def rewrap_reply(private: rsa.RSAPrivateKey, body: bytes) -> dict[str, str]:
    claims = json.loads(body)["signedRequestToken"].split(".")[1]
    request = json.loads(
        json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))[
            "requestBody"
        ]
    )
    data_key = private.decrypt(
        base64.b64decode(request["keyAccess"]["wrappedKey"]), _OAEP
    )
    client = serialization.load_pem_public_key(request["clientPublicKey"].encode())
    assert isinstance(client, rsa.RSAPublicKey)
    return {
        "entityWrappedKey": base64.b64encode(client.encrypt(data_key, _OAEP)).decode()
    }


def run_operation(
    method: str,
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: KasConfig,
    private: rsa.RSAPrivateKey,
) -> tuple[Path, Callable[[], None]]:
    source = directory / "input"
    source.write_bytes(_PAYLOAD)
    destination = directory / "output"
    if method == "PublicKey":
        return destination, lambda: create_tdf(
            source, destination, kas=config, attribute=_ATTRIBUTE
        )

    archive = directory / "archive.tdf"
    with monkeypatch.context() as patch:
        patch.setattr(KasConfig, "_post", lambda *_: key_reply(private))
        create_tdf(source, archive, kas=config, attribute=_ATTRIBUTE)
    return destination, lambda: open_tdf(archive, destination, kas=config)


def assert_request(requests: list[Request], method: str) -> None:
    (request,) = requests
    assert request.method == "POST"
    assert request.path == f"/kas.AccessService/{method}"
    assert request.authorization == f"Bearer {_TOKEN}"
    assert isinstance(json.loads(request.body), dict)


@pytest.mark.parametrize("method", ["PublicKey", "Rewrap"])
@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_kas_redirect_never_forwards_bearer_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_key: rsa.RSAPrivateKey,
    method: str,
    status: int,
) -> None:
    with (
        serve(lambda _: Reply()) as (untrusted, received),
        serve(lambda _: Reply(status, headers=(("Location", untrusted),))) as (
            endpoint,
            requests,
        ),
    ):
        destination, run = run_operation(
            method, tmp_path, monkeypatch, KasConfig(endpoint, _TOKEN), private_key
        )
        before = set(tmp_path.iterdir())
        with pytest.raises(TdfError, match=f"HTTP {status}"):
            run()
        assert not destination.exists()
        assert set(tmp_path.iterdir()) == before
        assert_request(requests, method)
        assert received == []


@pytest.mark.parametrize("method", ["PublicKey", "Rewrap"])
@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        pytest.param(Reply(401), TdfError, "HTTP 401", id="unauthenticated"),
        pytest.param(
            Reply(403, b'{"code":"permission_denied"}'),
            AccessDenied,
            "KAS denied access",
            id="permission-denied",
        ),
        pytest.param(
            Reply(403, b'{"code":"other"}'), TdfError, "HTTP 403", id="other-forbidden"
        ),
        pytest.param(
            Reply(403, b'["permission_denied"]'),
            TdfError,
            "HTTP 403 with invalid JSON",
            id="array-forbidden",
        ),
        pytest.param(Reply(503), TdfError, "HTTP 503", id="unavailable"),
        pytest.param(Reply(body=b"{"), TdfError, "invalid JSON", id="invalid-json"),
        pytest.param(Reply(body=b"[]"), TdfError, "invalid JSON", id="json-array"),
        pytest.param(
            Reply(body=b'{"kid":"first","kid":"second"}'),
            TdfError,
            "invalid JSON",
            id="duplicate-field",
        ),
    ],
)
def test_kas_failed_or_malformed_reply_leaves_no_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_key: rsa.RSAPrivateKey,
    method: str,
    reply: Reply,
    error: type[TdfError],
    message: str,
) -> None:
    with serve(lambda _: reply) as (endpoint, requests):
        destination, run = run_operation(
            method, tmp_path, monkeypatch, KasConfig(endpoint, _TOKEN), private_key
        )
        before = set(tmp_path.iterdir())
        with pytest.raises(error, match=message) as failure:
            run()
        assert type(failure.value) is error
        assert not destination.exists()
        assert set(tmp_path.iterdir()) == before
        assert_request(requests, method)


@pytest.mark.parametrize("method", ["PublicKey", "Rewrap"])
@pytest.mark.parametrize("framing", ["exact-limit", "one-over-limit", "early-eof"])
def test_kas_checks_http_body_size_and_completeness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_key: rsa.RSAPrivateKey,
    method: str,
    framing: str,
) -> None:
    def respond(request: Request) -> Reply:
        message = (
            key_reply(private_key)
            if method == "PublicKey"
            else rewrap_reply(private_key, request.body)
        )
        body = json.dumps(message).encode()
        if framing == "early-eof":
            return Reply(body=body, headers=(("Content-Length", str(len(body) + 1)),))
        return Reply(body=body.ljust(_LIMIT + (framing == "one-over-limit"), b" "))

    with serve(respond) as (endpoint, requests):
        destination, run = run_operation(
            method, tmp_path, monkeypatch, KasConfig(endpoint, _TOKEN), private_key
        )
        before = set(tmp_path.iterdir())
        if framing == "exact-limit":
            run()
            if method == "PublicKey":
                with ZipFile(destination) as archive:
                    assert archive.testzip() is None
            else:
                assert destination.read_bytes() == _PAYLOAD
        else:
            with pytest.raises(TdfError, match="size limit|Incomplete KAS"):
                run()
            assert not destination.exists()
            assert set(tmp_path.iterdir()) == before
        assert_request(requests, method)


def issuer_metadata(issuer: str) -> Reply:
    return Reply(
        body=json.dumps(
            {"issuer": issuer, "token_endpoint": f"{issuer}/token"}
        ).encode()
    )


def test_oauth_token_redirect_does_not_forward_secret_or_contact_kas(
    tmp_path: Path,
) -> None:
    def respond(request: Request) -> Reply:
        if request.path.endswith("/.well-known/openid-configuration"):
            return issuer_metadata(issuer)
        return Reply(307, headers=(("Location", f"{untrusted}/token"),))

    with (
        serve(lambda _: Reply()) as (untrusted, received),
        serve(respond) as (issuer, requests),
    ):
        config = KasConfig.from_client_credentials(untrusted, issuer, "id", "secret")
        source = tmp_path / "source"
        source.write_bytes(_PAYLOAD)
        destination = tmp_path / "output"
        with pytest.raises(
            TdfError, match="OAuth client credentials returned HTTP 307"
        ):
            create_tdf(source, destination, kas=config, attribute=_ATTRIBUTE)
        assert requests == [
            Request("GET", "/.well-known/openid-configuration", None, b""),
            Request(
                "POST", "/token", "Basic aWQ6c2VjcmV0", b"grant_type=client_credentials"
            ),
        ]
        assert received == []
        assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize(
    "invalid_token",
    [
        {"token_type": "Basic", "access_token": "test"},
        {"token_type": "Bearer"},
        {"token_type": "Bearer", "access_token": "test token"},
        {"token_type": "Bearer", "access_token": "test", "expires_in": 0},
        {"token_type": "Bearer", "access_token": "test", "expires_in": -1},
        {"token_type": "Bearer", "access_token": "test", "expires_in": True},
        {"token_type": "Bearer", "access_token": "test", "expires_in": "100"},
    ],
)
def test_invalid_oauth_token_never_reaches_kas(
    tmp_path: Path, invalid_token: dict[str, object]
) -> None:
    def respond(request: Request) -> Reply:
        if request.path.endswith("/.well-known/openid-configuration"):
            return issuer_metadata(issuer)
        return Reply(body=json.dumps(invalid_token).encode())

    with (
        serve(lambda _: Reply()) as (kas, received),
        serve(respond) as (issuer, requests),
    ):
        config = KasConfig.from_client_credentials(kas, issuer, "id", "secret")
        source = tmp_path / "source"
        source.write_bytes(_PAYLOAD)
        with pytest.raises(TdfError, match="token"):
            create_tdf(source, tmp_path / "output", kas=config, attribute=_ATTRIBUTE)
        assert [r.path for r in requests] == [
            "/.well-known/openid-configuration",
            "/token",
        ]
        assert received == []
        assert list(tmp_path.iterdir()) == [source]


def test_oauth_failed_refresh_never_reuses_expired_token_and_can_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private_key: rsa.RSAPrivateKey
) -> None:
    now = 100.0
    token_attempts = 0

    def respond(request: Request) -> Reply:
        nonlocal token_attempts
        if request.path.endswith("/.well-known/openid-configuration"):
            return issuer_metadata(issuer)
        token_attempts += 1
        if token_attempts == 2:
            return Reply(503)
        return Reply(
            body=json.dumps(
                {
                    "token_type": "Bearer",
                    "access_token": f"token-{token_attempts}",
                    "expires_in": 10,
                }
            ).encode()
        )

    monkeypatch.setattr(_kas_auth, "monotonic", lambda: now)
    with (
        serve(lambda _: Reply(body=json.dumps(key_reply(private_key)).encode())) as (
            kas,
            kas_requests,
        ),
        serve(respond) as (issuer, issuer_requests),
    ):
        config = KasConfig.from_client_credentials(kas, issuer, "id", "secret")
        source = tmp_path / "source"
        source.write_bytes(_PAYLOAD)
        create_tdf(source, tmp_path / "first", kas=config, attribute=_ATTRIBUTE)
        now = 110.0
        with pytest.raises(TdfError, match="HTTP 503"):
            create_tdf(source, tmp_path / "second", kas=config, attribute=_ATTRIBUTE)
        assert not (tmp_path / "second").exists()
        assert [request.authorization for request in kas_requests] == ["Bearer token-1"]
        create_tdf(source, tmp_path / "third", kas=config, attribute=_ATTRIBUTE)
        create_tdf(source, tmp_path / "fourth", kas=config, attribute=_ATTRIBUTE)
        assert [request.authorization for request in kas_requests] == [
            "Bearer token-1",
            "Bearer token-3",
            "Bearer token-3",
        ]
        assert [request.path for request in issuer_requests] == [
            "/.well-known/openid-configuration",
            "/token",
            "/token",
            "/token",
        ]
        assert not list(tmp_path.glob(".tdf-*"))
