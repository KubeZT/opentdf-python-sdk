# TDF capability matrix

These rows describe the tested ZIP profiles. The shared suite runs against a
fresh local OpenTDF Platform `service/v0.31.0` with a packaged Rust crate,
an installed Python wheel, Java `0.19.1`, and Go `sdk/v0.35.0`. See the
[reference pins](testing.md).

| Capability | ZIP profile | Writers tested | Readers tested | Shared check |
| --- | --- | --- | --- | --- |
| Single attribute, RSA-2048 KAS grant | Java-compatible | Rust, Python, Java, Go | Rust, Python, Java, Go | [Base round trips](../tests/interop/matrix.py) |
| Single attribute, RSA-2048 KAS grant | Spec | Rust, Python | Rust, Python, Go | [Base round trips](../tests/interop/matrix.py) |
| Multiple attributes in one grant with encrypted UTF-8 metadata | Java-compatible | Rust, Python, Java, Go | Rust, Python, Java, Go | [Feature round trips](../tests/interop/matrix.py) |
| Multiple attributes in one grant with encrypted UTF-8 metadata | Spec | Rust, Python | Rust, Python, Go | [Feature round trips](../tests/interop/matrix.py) |
| HS256 and caller-key RS256 signed assertions | Java-compatible | Rust, Python, Java, Go | Rust, Python, Java, Go | [Assertion round trips](../tests/interop/matrix.py) |
| HS256 and caller-key RS256 signed assertions | Spec | Rust, Python | Rust, Python, Go | [Assertion round trips](../tests/interop/matrix.py) |
| Assertion key mismatch, replay, tampering, and required IDs | Both | [Shared fixtures](../tests/vectors/zip-profile-v1.json) | Rust, Python | [Offline conformance](../tests/conformance/README.md) and [live rejection cases](../tests/interop/matrix.py) |
| All-of authorization and metadata ciphertext integrity | Both | Java (Java-compatible), Rust (Spec) | Rust, Python | [Entitlement and tamper checks](../tests/interop/matrix.py) |
| Explicit KAS routing with the producer and its IdP offline | Both | Rust, Python | Rust, Python | [Two-site test](../tests/interop/federation.py) |
| Large-file round trips | Both | Rust, Python | Rust, Python | [Large-payload suite](../tests/interop/large_payloads.py) |
| ZIP64 round trips at 8 GiB + 1 byte | Both | Rust (Java-compatible), Python (Spec) | Rust, Python | [ZIP64 case](../tests/interop/large_payloads.py) |

The feature round trips compare payload bytes and decrypted metadata. The
authorization case checks access with both required values and denial with
one or zero. Each reader also proves the partial identity can open a TDF
requiring just its assigned value.

Metadata is optional in these profiles. AES-GCM authenticates the ciphertext
when it is present. Deleting the metadata field has the same effect as omitting
it at creation.

Each signature covers its statement and the ordered payload segment tags.
RS256 identifies the signer through the caller's configured public key.
Require an assertion ID on open when its presence matters.

Run `make test-e2e` to reproduce the matrix locally. See the
[interop guide](../tests/interop/README.md) for setup and the larger ZIP64 cases.
