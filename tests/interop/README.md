# Interoperability

Run the matrix from either checkout with `make test-e2e`. It starts a
local OpenTDF Platform, Keycloak, and PostgreSQL, provisions test identities,
and tears down the stack afterward. The entry point selects the E2E
test in Cargo or pytest. The regular local suite runs without Docker. The test uses an external Cargo crate
that depends on the built Rust package and installs the Python wheel in a
clean virtual environment. Java and Go use the released upstream SDKs.

You'll need Docker Compose, OpenSSL, Go 1.26.10, JDK 17, Maven, Rust, and a
Python virtual environment with the Python SDK's `requirements-dev.txt`
installed. The first run can download toolchain dependencies and images.
The checkouts default to sibling directories. Set `PYTHON_SDK` in the Rust
checkout or `RUST_SDK` in the Python checkout to override their locations.

```sh
make test-e2e PYTHON=/path/to/venv/bin/python
```

The matrix exercises Java and Go in both directions with each native SDK,
Rust ↔ Python, and round trips within each SDK. Java uses the legacy ZIP
layout. Go reads both tested layouts. Each run also checks shared-KAS
authorization, failed reads, and empty native payloads. It also verifies
that the shared harness and [conformance corpus](../conformance/README.md)
match across checkouts.

To reuse a trusted checkout of the pinned release, set
`OTDF_TEST_PLATFORM_SOURCE`. Set `OTDF_TEST_PLATFORM_BINARY` as well to
reuse an existing build. The runner still provisions a fresh test stack.

For a pre-provisioned platform, use the [manual KAS setup](java/local-kas.md)
and run `sh tests/interop/matrix.sh` directly. The [federation cases](federation.md) define what
the next milestone must prove with independent sites.
