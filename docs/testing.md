# Testing and conformance

The initialization tests exercise the installed package's version API.
Both SDKs use the same small version fixture in `tests/vectors/`. TDF
behavior has no test results at this stage.

## Upstream references

| Source | Use |
| --- | --- |
| [Published specification](https://opentdf.io/spec) | Format, protocol, schema, and policy terminology |
| [Specification repository](https://github.com/opentdf/spec) | Normative text, schema revisions, and the upstream [VERSION file](https://github.com/opentdf/spec/blob/main/VERSION) |
| [Upstream tests](https://github.com/opentdf/tests) | [Cross-client harness](https://github.com/opentdf/tests/tree/main/xtest), upstream test cases, and fixture provenance |
| [Java SDK](https://github.com/opentdf/java-sdk) | Use the separation of the core library, examples, CLI, and test tooling as an organizational reference. Use the Java SDK as an interoperability peer. |

The three repositories each declare BSD-3-Clause-Clear in their license
files. This scaffold references them without importing code, schemas,
fixtures, or upstream documentation. Before importing materials, check
the license at the exact revision and retain the applicable copyright
notice, license text, and disclaimer with the imported materials and
their distributions. Record source paths and fixture checksums. The
[OpenTDF site terms](https://opentdf.io/terms-of-service) identify
OpenTDF and related logos as project trademarks.

## Versioning and interoperability

The upstream VERSION file on main showed 4.3.0 during initialization.
The first supported profile will be selected and pinned during implementation.

Pin the spec revision, schema revision, upstream test revision, peer SDK
release or commit, and platform/KAS version for each compatibility profile.
Record the SDK version independently of the TDF specification and schema
versions. Published examples use `manifest.json`. Deployed conventions may
use `0.manifest.json`. Exercise manifest and payload member naming and
resolution in both directions under each claimed profile, and capture
any observed differences with fixture provenance. Compatibility claims
require evidence for the pinned versions.

Run a producer/consumer matrix for Rust, Python, and a pinned official SDK
such as Java, including both Rust-to-Python and Python-to-Rust. Compare the
recovered payload, policy and assertion behavior, and failure outcomes.
Use deterministic randomness only in isolated known-answer tests that
require exact bytes. Keep the two production implementations native.
Run service-dependent cases against explicitly configured local peers.

The SDKs are intended for generic TDF use. KubeZT integration will own
the `.kube` extension and package workflow. Its future compatibility
tests should verify that the encrypted Kube package is carried as the
payload of a standard TDF envelope, with the Kube and TDF manifests
retaining their separate roles.

## Test organization

| Path | Coverage to add |
| --- | --- |
| [`tests/conformance/`](../tests/conformance/) | Map each in-scope normative requirement and schema constraint to positive, negative, and boundary cases. |
| [`tests/interop/`](../tests/interop/) | Match peer versions and available capabilities to versioned producer/consumer results. |
| [`tests/malformed/`](../tests/malformed/) | Exercise invalid schemas and archives, truncation, duplicate or ambiguous members, streaming failures, and resource limits. |
| [`tests/security/`](../tests/security/) | Exercise cryptographic failure, ciphertext and metadata tampering, policy binding, authorization and key-access failures, and output handling on failure. |
| [`tests/vectors/`](../tests/vectors/) | Keep byte-identical inputs and shared expectations in both repositories. |

When implementation begins, maintain a requirements matrix with a stable
test ID, spec or schema locator at a pinned revision, applicable profile,
expected behavior, fixture provenance, and Rust and Python test IDs.
Record unsupported capabilities and untested requirements explicitly.
Promote minimized property-test failures into named regression cases.
Use the target of 10–20 times the meaningful coverage of a basic
implementation to drive distinct cases and failure paths. Track exercised
requirements and outcomes independently of test count.
