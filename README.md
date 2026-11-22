# OpenTDF Python SDK

Python library for the Trusted Data Format (TDF), a format for packaging
encrypted data with its access policy.

## Use it in a local project

With Python 3.10 or newer, install the checkout into your project's virtual
environment:

```sh
python -m pip install -e /path/to/opentdf-python-sdk
```

The SDK has no runtime dependencies. You can also run the
[example script](examples/embedding.py) to check the install.

## Work on the SDK

From this checkout:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install --no-build-isolation -e .
make check
```

`make check` runs Ruff, mypy, and pytest. Use `make test` to run just the
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
