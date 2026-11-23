# Interoperability

Run the matrix from either checkout with `make test-e2e`. It starts a
local OpenTDF Platform, Keycloak, and PostgreSQL, provisions test identities,
and tears down the stack afterward. The entry point selects the E2E
test in Cargo or pytest. The regular local suite runs without Docker. The test uses an external Cargo crate
that depends on the built Rust package and installs the Python wheel in a
clean virtual environment. Java and Go use the released upstream SDKs.

You'll need Docker Compose, OpenSSL, Go 1.26.10, JDK 17, Maven, Rust, and a
Python virtual environment set up with `pip install -r requirements-dev.txt`
from the Python checkout. The first run can download toolchain dependencies and images.
The checkouts default to sibling directories. Set `PYTHON_SDK` in the Rust
checkout or `RUST_SDK` in the Python checkout to override their locations.

```sh
make test-e2e PYTHON=/path/to/venv/bin/python
```

The interoperability matrix exercises Java and Go in both directions with each native SDK,
Rust ↔ Python, and round trips within each SDK. Java uses the legacy ZIP
layout. Go reads both tested layouts. Each run also checks shared-KAS
authorization, failed reads, and empty native payloads. The local stack
enables the pinned Platform's P-256 preview and tests EC wrapping, EC
rewrap sessions, platform discovery, and Keycloak client credentials. With the self-starting
platform, the matrix also verifies multiple policy attributes and encrypted
UTF-8 metadata across all four SDKs. The
[capability matrix](../../docs/capabilities.md) lists the profiles and tested peers.
The suite also verifies
that the shared harness and [conformance corpus](../conformance/README.md)
match across checkouts.

To reuse a trusted checkout of the pinned release, set
`OTDF_TEST_PLATFORM_SOURCE`. Set `OTDF_TEST_PLATFORM_BINARY` as well to
reuse an existing build. The runner still provisions a fresh test stack.

For a pre-provisioned platform, use the [manual KAS setup](java/local-kas.md)
and run `sh tests/interop/matrix.sh` directly. The [federation suite](federation.md) starts independent sites. Run it alone
with `make test-federation`.

## Large payloads

Run `make test-large` to build downstream consumers, start a fresh local KAS,
and compare generated binary payloads across both SDKs. The Rust test
consumer uses a release build. On macOS and Linux,
the suite checks peak resident memory in each consumer process. Each
operation must stay at or below 128 MiB, with growth at or below 32 MiB
between the 80 MiB and 256 MiB cases. Failed reads must leave no new output
or temporary file.

Set `OTDF_TEST_ZIP64=1` to include the 8 GiB + 1 byte ZIP64 round trips. Set
`OTDF_TEST_HUNDREDS_GIB=1` to exercise adaptive segmentation at 256 GiB.
Allow about 25 GiB of free temporary disk for the ZIP64 case or 520 GiB
for the 256 GiB case. Both are opt-in. The tests generate and discard
their files locally.
