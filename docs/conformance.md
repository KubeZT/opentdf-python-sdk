# OpenTDF conformance coverage

`make test-conformance` runs the shared offline ZIP corpus in either SDK.
The [live matrix](capabilities.md) adds packaged SDK round trips through KAS.

## References reviewed

- [Specification 4.3.0](https://github.com/opentdf/spec/tree/c6592bafc5e4e0ef9623ba8211bec2e465704c2a) and the published [manifest](https://opentdf.io/spec/schema/opentdf/manifest) and [assertion binding](https://opentdf.io/spec/schema/opentdf/assertion_binding) pages. Keep the tag and published docs distinct. The tag's `schema/test` only has a README.
- [Java SDK 0.19.1](https://github.com/opentdf/java-sdk/tree/8e6f8bcb032ac3da5dae8151acedfcc6af734dac), including `sdk/src/test` and the optional crypto-provider test modules.
- [Go SDK 0.35.0](https://github.com/opentdf/platform/tree/b04847659c0fe82a3b2cf47ca61f8dbba33218e6/sdk), including ZIP streaming, auth, and experimental TDF tests.
- [OpenTDF cross-SDK tests](https://github.com/opentdf/tests/tree/da2d90258682ef74944a7f61ad1f9d8cc709023c/xtest), including golden TDFs, ZIP checking, assertion cases, and live policy cases.

## Coverage by feature

The reference tests below are a source inventory. The live matrix uses the
pinned releases as readers and writers.

| Area | Rust and Python coverage | Reference cases and gaps |
| --- | --- | --- |
| ZIP layout and manifest | Both manifest layouts, duplicate fields, contradictory headers, directory bounds, ZIP64 sentinels, and rejection of every shorter prefix of each known-answer archive before key release | Java `ZipReaderTest` and `ZipWriterTest`. Go `internal/zipstream` and `tdf_spec_version_test.go`. Upstream `test_zip_conformance.py`. The shared corpus covers local equivalents of several upstream mutations. Run the remaining upstream cases directly and add manifest-schema validation. |
| Encryption and payload integrity | Fixed AES-256-GCM ciphertext, segment sizes and tags, root HMAC, late tamper rejection, and exact byte recovery | Java `AesGcmTest` and `TDFRootSignatureTest`. Go `tdf_test.go`, `fuzz_test.go`, and `tdf_segment_defaults_test.go`. Add upstream legacy hash modes when supported. |
| Streaming and resource limits | Bounded memory, adaptive segment plans through the GCM/metadata bounds and fixed-buffer allocation checks, output cleanup on late failure, and opt-in 8 GiB and 256 GiB cross-SDK files | Go `tdf_readat_test.go`, `chunked_test.go`, and ZIP fuzzers. Upstream `test_zip64.py` and range fixtures. Random access and HTTP ranges are gaps. |
| Policy and authorization | Single grant, policy binding for both profiles, multiple attributes, shared KAS, all-of access, invalid credentials, denial, and local routing with producer offline | Java `PlannerTest` and `AutoconfigureTest`. Go `granter_test.go`, `key_splitter_test.go`, and experimental split tests. Upstream `test_abac.py`. Add AnyOf, Hierarchy, multi-grant split, and obligation cases as support lands. |
| Encrypted metadata | UTF-8 metadata, peer round trips, malformed framing, tag failures, and nonce reuse rejection | Go `key_access_test.go` and `tdf_test.go`; Java `TDFTest`. Extend coverage with upstream golden containers and metadata across key splits. |
| Signed assertions | HS256 and caller-pinned RS256, string statements, independent JWS vectors, required IDs, key mismatch, tampering and payload replay | Java `TDFTest`. Go `assertion_test.go` and `null_statement_test.go`. Upstream `test_tdf_assertions.py`. Add the upstream object-valued statement fixtures if the SDKs support that wire form. |
| KAS keys and transport | RSA-2048 and P-256 wrapping and rewrap sessions, malformed grants, explicit origin, and loopback HTTP checks for redirects, truncation, and the response size limit | Java `KeyTypeTest`, `ECKeyPairTest`, `KASClientTest`, and optional PQC/FIPS test modules. Go `key_access_test.go`, `tdf_hybrid_test.go`, and `kas_client_test.go`. Other curves, PQC, and FIPS need separate coverage. |
| Discovery and token lifecycle | Configured platform discovery, OIDC client credentials, token expiry and failed-refresh retry, explicit routes, and caller bearer tokens | Java `DiscoveryTest`, `TokenSourceTest`, and `DPoPRetryInterceptorTest`. Go `discovery_test.go` and `auth` tests. Interactive authorization, token exchange, and DPoP need separate coverage. |
| Legacy, advanced formats, and workflow APIs | Two ZIP profiles | Upstream `test_legacy.py`, `test_pqc.py`, and `test_audit_logs_integration.py`. Go experimental TDF and split suites. Legacy versions, bulk APIs, and platform workflows are outside the current ZIP corpus. |

## Upstream golden archives

The Java 0.19.1 golden uses the ZIP layout and cryptographic encodings
expected for a single RSA grant. Its empty policy is rejected by both
readers before KAS. The archive is usable for independent cryptographic
checks. A positive end-to-end golden also needs a supported policy and
its original test key in the local KAS.
[Pinned upstream golden](https://github.com/opentdf/tests/blob/da2d90258682ef74944a7f61ad1f9d8cc709023c/xtest/golden/xstext-java-v0.19.1-8e6f8bc-GW2.79.0.tdf)

Keep generated fixtures local. For any upstream fixture brought into either
checkout, record its source, revision, license, and checksum.
