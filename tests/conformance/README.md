# ZIP profile conformance

The Rust and Python suites run the same
[fixture corpus](../vectors/zip-profile-v1.json). It defines 61 ZIP cases
and 114 layout-specific checks for the Java-compatible and spec ZIP profiles.
Two additional cases probe the ZIP reader with standalone foreign inputs.
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
| `P256-` | P-256 grant, ephemeral key presence and curve, and wrapped-key length | [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object) |
| `ASSERTION-` | HS256 and RS256 JWS, canonical text, required and duplicate IDs, bad signatures and statement changes, object-valued statement rejection, caller key pins, and payload binding | [Assertion binding](https://opentdf.io/spec/schema/opentdf/assertion_binding) |

The `FOREIGN-` cases use a synthetic XML TDF object and a binary `L1L`
header. Both readers must reject these inputs without requesting a key or
writing output. See the [separate profile acceptance cases](../../docs/profiles.md).

The corpus was generated independently of the SDKs with AES-256-GCM
through PyCA and Python's HMAC-SHA256. It uses the public test key
`00 01 … 1f`, IVs 1 and 2 encoded in 12-byte big-endian form, and a
16-byte segment size. The RSA wrapped key is a placeholder for the
stubbed key release. The expected plaintext, ciphertext, tags, and HMACs
are fixed in the corpus. Neither SDK generates its own expected answers.

Assertion vectors use Python's HMAC and PyCA RSA with the corpus segment
tags and fixed string statements. The corpus records the signatures and
public test keys.

The P-256 grant uses disposable fixed curve points and a known wrapped key.

The suite replaces key release with the known fixture key. It checks that
structural failures never request that key and that rejected files leave
neither a destination nor a temporary output. The live interoperability
suite tests actual RSA and P-256 wrapping, KAS transport, and authorization.

Run `make test-conformance` in either checkout. Rust's `zip_profiles.rs`
runs as a library test so it can stub key release. Python's
`test_zip_profiles.py` uses pytest. See the [coverage audit](../../docs/conformance.md)
for the upstream test and specification references.
For shared changes, keep both JSON copies byte-identical. Add cases for
newly supported profile features alongside their specification references.
