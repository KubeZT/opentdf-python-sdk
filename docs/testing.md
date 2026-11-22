# Testing

Run `make check` for local tests. The suite covers file round trips,
segment boundaries, malformed containers, integrity failures, and size
limits without a running platform. Use the
[interoperability tests](../tests/interop/README.md) for the live KAS matrix.

## Compatibility profile

| Reference | Pin |
| --- | --- |
| [TDF specification](https://github.com/opentdf/spec/releases/tag/4.3.0) | `4.3.0` (`c6592ba`) |
| [Java SDK](https://github.com/opentdf/java-sdk/releases/tag/v0.19.1) | `0.19.1` (`8e6f8bc`) |
| [OpenTDF Platform](https://github.com/opentdf/platform/releases/tag/service/v0.31.0) | `service/v0.31.0` (`45a10ad`) |

The Java 0.19.1 ZIP profile stores `0.payload` and `0.manifest.json`.
The manifest declares schema version `4.3.0`, while the
[published container specification](https://opentdf.io/spec/schema/opentdf)
names the entry `manifest.json`. The SDKs implement the tested Java profile.

| Area | What to verify |
| --- | --- |
| ZIP and manifest | Stored entries with unique names, a payload reference, supported schema and algorithms, and bounded sizes. |
| Segments and integrity | Empty and multi-segment payloads, authentication of every segment, root integrity, and no destination file on failure. |
| Key access and policy | One RSA-wrapped key, one data attribute, policy binding, an entitled read, and a policy-denied read with valid credentials. |
| Interoperability | Every Rust, Python, and Java writer and reader combination recovers identical bytes through the pinned KAS. |

Federation and disconnected access need a separate two-KAS test.
KubeZT owns the `.kube` extension and passes its package to the SDK as
payload bytes.

## Fixtures

Keep shared inputs and expected outcomes byte-identical. Record the source,
revision, license, and checksum of anything brought in from the
[upstream suite](https://github.com/opentdf/tests). Link each conformance case
to the specific requirement it exercises. Keep live KAS credentials and
generated keys out of fixtures.
