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

from opentdf_sdk import create_tdf, open_tdf

kas = {
    "kas_url": "http://localhost:18880",
    "access_token": os.environ["OTDF_ACCESS_TOKEN"],
}
create_tdf(
    "input.bin",
    "archive.tdf",
    attribute="https://example.com/attr/department/value/engineering",
    **kas,
)
open_tdf("archive.tdf", "recovered.bin", **kas)
```

By default, `create_tdf` writes the Java 0.19.1 ZIP layout with `0.payload`
and `0.manifest.json`. Pass `profile="spec"` to write the OpenTDF 4.3.0
profile with `manifest.json`, the version in the payload reference, and the
base64-encoded raw policy HMAC. `open_tdf` detects either profile from the
archive and checks that the manifest fields match.

Both profiles support one RSA-2048 KAS key, one policy attribute, and payloads
up to 64 MiB. KAS denial raises `AccessDenied` and leaves the destination
absent. These profiles cover a subset of the TDF specification.

## Use a trusted KAS endpoint for an archived origin

When the archive names a KAS origin that differs from your reachable
endpoint, pass the expected origin as `manifest_kas_url` alongside
`kas_url` and an access token for that endpoint.

```python
kas = {
    "kas_url": "http://localhost:18880",
    "manifest_kas_url": "https://kas.example.com",
    "access_token": os.environ["OTDF_ACCESS_TOKEN"],
}
open_tdf("archive.tdf", "recovered.bin", **kas)
```

`create_tdf` records the same configured origin in new archives.
`open_tdf` requires the archive's key access object to match that origin
exactly, after trimming an optional trailing slash from the configuration.
Public key and rewrap calls use `kas_url`. Both URLs must be HTTPS origins
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
[testing guide](docs/testing.md) for fixtures and planned conformance coverage.

## Build a wheel and source distribution

In the same virtual environment, run `make package`. Both files land in
`dist/`. To try the wheel in a different virtual environment:

```sh
python -m pip install /path/to/opentdf-python-sdk/dist/opentdf_python_sdk-0.1.0-py3-none-any.whl
```

## License

[Apache 2.0](LICENSE) · [Attribution](NOTICE)
