# ZIP profile conformance

The Rust and Python suites run the same
[fixture corpus](../vectors/zip-profile-v1.json). It defines 56 cases and
104 profile-specific checks for the Java-compatible and spec ZIP profiles.
The spec reference is the pinned OpenTDF [4.3.0 tag](https://github.com/opentdf/spec/tree/4.3.0).
Java-specific checks cover the ZIP layout and binding encoding used by
[Java SDK 0.19.1](https://github.com/opentdf/java-sdk/releases/tag/v0.19.1).

| Case ID prefix | Behavior checked | Format reference |
| --- | --- | --- |
| `BASE-`, `SPEC-REFERENCED-` | Known plaintext from fixed ciphertext across two segments, inherited segment sizes, and referenced ZIP payloads | [ZIP TDF payload](https://opentdf.io/spec/schema/opentdf/payload) |
| `ZIP-`, `MANIFEST-` | Root manifest choice, entry count, ZIP header agreement, truncated structure, malformed JSON, and duplicate fields | [TDF manifest](https://github.com/opentdf/spec/blob/4.3.0/schema/manifest-json.md) and [ZIP format](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) |
| `JAVA-`, `SPEC-`, `PAYLOAD-`, `METHOD-` | Profile-specific version placement, safe payload references, stored payload size, and supported encryption method | [TDF manifest](https://github.com/opentdf/spec/blob/4.3.0/schema/manifest-json.md) |
| `GRANT-`, `POLICY-` | Single-grant shape, KAS origin, policy binding encoding, and attribute requirements | [Key Access Object](https://github.com/opentdf/spec/blob/4.3.0/schema/KeyAccessObject.md) and [Policy Object](https://github.com/opentdf/spec/blob/4.3.0/schema/PolicyObject.md) |
| `INTEGRITY-`, `*-BINDING-TAMPER` | Segment sizes, algorithm IDs, authentication tags, root integrity, and rejection on policy or ciphertext changes | [Integrity information](https://opentdf.io/spec/schema/opentdf/integrity_information) |
| `ASSERTION-` | HS256 and RS256 JWS, canonical text, required and duplicate IDs, bad signatures and statement changes, caller key pins, and payload binding | [Assertion binding](https://opentdf.io/spec/schema/opentdf/assertion_binding) |

The corpus was generated independently of the SDKs with AES-256-GCM
through PyCA and Python's HMAC-SHA256. It uses the public test key
`00 01 … 1f`, IVs 1 and 2 encoded in 12-byte big-endian form, and a
16-byte segment size. The wrapped key bytes are a placeholder for the
stubbed key release. The expected plaintext, ciphertext, tags, and HMACs
are fixed in the corpus. Neither SDK generates its own expected answers.

Assertion vectors use Python's HMAC and PyCA RSA with the corpus segment
tags and fixed string statements. The corpus records the signatures and
public test keys.

The suite replaces key release with the known fixture key. It checks that
structural failures never request that key and that rejected files leave
neither a destination nor a temporary output. The live interoperability
suite tests actual RSA wrapping, KAS transport, and authorization.

Run `make test-conformance` in either checkout. Rust's `zip_profiles.rs`
runs as a library test so it can stub key release. Python's
`test_zip_profiles.py` uses pytest. See the [coverage audit](../../docs/conformance.md)
for the upstream test and specification references.
For shared changes, keep both JSON copies byte-identical. Add cases for
newly supported profile features alongside their specification references.
