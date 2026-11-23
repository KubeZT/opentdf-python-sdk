# OpenTDF Python SDK

Python library for the Trusted Data Format (TDF), a format for packaging
encrypted data with its access policy.

## Use it in a local project

With Python 3.10 or newer, install the checkout into your project's virtual
environment:

```sh
python -m pip install -e /path/to/opentdf-python-sdk
```

## Create and open a TDF

Supply an access token from the platform's identity provider and the URL of
the KAS you trust. The destination path must be new.

```python
import os

from opentdf_sdk import KasConfig, create_tdf, open_tdf

kas = KasConfig("http://localhost:18880", os.environ["OTDF_ACCESS_TOKEN"])
create_tdf(
    "input.bin",
    "archive.tdf",
    attribute="https://example.com/attr/department/value/engineering",
    kas=kas,
)
open_tdf("archive.tdf", "recovered.bin", kas=kas)
```

By default, `create_tdf` writes the Java 0.19.1 ZIP layout with `0.payload`
and `0.manifest.json`. Pass `profile="spec"` to write the OpenTDF 4.3.0
profile with `manifest.json`, the version in the payload reference, and the
base64-encoded raw policy HMAC. `open_tdf` detects either profile from the
archive and checks that the manifest fields match.

Pass `attributes=[first_fqn, second_fqn]` in place of `attribute=` to use
multiple policy attributes. Pass `metadata="your text"` to include encrypted
UTF-8 metadata. `open_tdf_with_metadata(...)` decrypts the payload and returns
the metadata if present.

Both profiles support one RSA-2048 or P-256 KAS grant and payloads up to
2 TiB, subject to the 4 MiB manifest limit. The SDK processes regular
files in segments and uses ZIP64 when needed. The writer starts with 2 MiB segments and increases the size
up to 64 MiB for large files. KAS denial raises `AccessDenied` and leaves
the destination absent. These profiles cover a subset of the TDF
specification.

Pass `assertions=[AssertionConfig(...)]` to sign assertions. Omit the signing
key to use the TDF's key with HS256, or pass a private RSA PEM in
`signing_key_pem` for RS256. On open, use `required_assertions` to require
assertion IDs and `assertion_verification_keys` to supply trusted RS256
public keys by ID.

## Discover a KAS or use OAuth client credentials

Pass a `KasConfig` as `kas=` to create or open a TDF.
`KasConfig.discover(platform, token)` reads the configured platform's
well-known document. It uses the advertised base KAS, or the co-hosted
KAS when no base key is configured.

For OAuth, use `KasConfig.from_client_credentials(kas, issuer, id, secret)`
or `KasConfig.discover_with_client_credentials(platform, issuer, id, secret)`.
Platform discovery checks the configured issuer before using it. OIDC
discovery keeps token requests on that issuer's origin.

Use `config.with_key_algorithm("ec:secp256r1")` to choose P-256 wrapping
and rewrap sessions. Pass `key_id=` to `create_tdf` to pin the wrapping key.

## Use a trusted KAS endpoint for an archived origin

When the archive names a KAS origin that differs from your reachable
endpoint, use `with_manifest_origin` to configure the archived origin.

```python
kas = KasConfig("http://localhost:18880", os.environ["OTDF_ACCESS_TOKEN"])
kas = kas.with_manifest_origin("https://kas.example.com")
open_tdf("archive.tdf", "recovered.bin", kas=kas)
```

`create_tdf` records the same configured origin in new archives.
`open_tdf` requires the archive's key access object to match that origin
exactly, after trimming an optional trailing slash from the configuration.
Public key and rewrap calls use the configured endpoint. Both URLs must be HTTPS origins
or loopback HTTP origins.

## Work on the SDK

From this checkout:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
make check
```

The requirements file installs the SDK in editable mode along with the
development tools. `make check` runs Ruff, mypy, and pytest. Use `make test` to run just the
tests or `make format` to apply formatting. See the
[testing guide](docs/testing.md) and [capability matrix](docs/capabilities.md).

## Build a wheel and source distribution

In the same virtual environment, run `make package`. Both files land in
`dist/`. To try the wheel in a different virtual environment:

```sh
python -m pip install /path/to/opentdf-python-sdk/dist/opentdf_python_sdk-0.1.0-py3-none-any.whl
```

See [paired releases](docs/release.md) to build and verify both SDK
packages together.

## License

[Apache 2.0](LICENSE) · [Attribution](NOTICE)
