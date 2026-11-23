# Additional TDF profiles

The release covers the ZIP layouts in the [capability matrix](capabilities.md).
The cases below define acceptance for future profile implementations. The
[offline suite](../tests/conformance/README.md) currently checks the ZIP reader
boundary with `FOREIGN-IC-TDF-XML`, `FOREIGN-NANOTDF-L1L`, and
`ASSERTION-OBJECT-STATEMENT`. These cases exercise format and input rejection.

## ACP 240 ZTDF

Acceptance depends on the delivery sponsor providing the applicable ACP 240
edition and supplements, authorized schemas and fixtures, and an independent
peer. The public OpenTDF specification describes the relationship to ZTDF and
leaves its required assertions to the separately maintained specification.
Prioritize these cases if ACP 240 becomes a delivery requirement.
[OpenTDF specification](https://github.com/opentdf/spec) ·
[ACP 240 announcement](https://www.virtru.com/newsroom/virtru-data-security-platform-enables-acp-240-adoption-among-allied-nations-and-technology-partners)

| Case | Planned acceptance |
| --- | --- |
| `ACP240-01` | Map each applicable requirement to the pinned edition or supplement. Validate the container, manifest, and security assertions against the sponsor's schemas and positive fixtures. |
| `ACP240-02` | Verify all mandatory assertions, including their binding to the security labels and payload wherever the edition requires it. Reject missing, altered, or transplanted assertions. |
| `ACP240-03` | Round-trip both ways with the designated peer. Verify authorized reads, unauthorized denial, and failure without output for modified labels, bindings, or ciphertext. |

## IC-TDF

Use ODNI's V2021-NOV XML releases with the XSD, Schematron rules, and examples.
The official packages share a TDF namespace, so profile acceptance requires the
IC-TDF constraints as well as the base schema. Use unclassified fixtures.
[IC-TDF.XML](https://archive.dni.gov/index.php/who-we-are/organizations/ic-cio/ic-technical-specifications/trusted-data-format) ·
[BASE-TDF.XML](https://archive.dni.gov/index.php/who-we-are/organizations/ic-cio/ic-technical-specifications/trusted-data-format-base)

| Source package | SHA-256 |
| --- | --- |
| [IC-TDF standalone](https://archive.dni.gov/files/documents/CIO/ICEA/Dec2022/IC-TDF/IC-TDF-Public-Standalone.zip) | `dd0400cc76c361d19abef3a6af30e16ca4a8e60657262c36b5bdb578c6326382` |
| [BASE-TDF standalone](https://archive.dni.gov/files/documents/CIO/ICEA/Dec2022/BASE-TDF/BASE-TDF-Public-Standalone.zip) | `3c43a2db264fab57df0efac10281ead5fd1842f0abc8ff6406428b4d6d19105d` |

| Case | Planned acceptance |
| --- | --- |
| `IC-TDF-01` | Validate the official minimal, object, and collection examples with the pinned schemas and rules. Reject wrong namespaces, missing required fields, and invalid cardinality. |
| `IC-TDF-02` | Verify metadata-to-payload bindings with the official binding examples and an independent verifier. Preserve required markings and reject altered metadata, data, and mismatched references. |
| `IC-TDF-03` | Verify encrypted round trips with an independent peer and paired test keys. Check denial and tamper cases for no output. Reject external entity resolution and unexpected network retrieval. |

## NanoTDF

Start with the historical `L1L` binary format. The pinned specification
contains signed and unsigned known-answer examples in sections 6.1 and 6.2.
Use the pinned Web SDK as the reference peer. Its next release removed
NanoTDF support.
[NanoTDF specification at `88b414f`](https://github.com/opentdf/spec/blob/88b414fb15759341710bc29d110abe09934032d7/schema/nanotdf/README.md) ·
[Web SDK `sdk-v0.8.0`](https://github.com/opentdf/web-sdk/tree/0677d7ae4609e18432150b0f3e9ebab8b78884fb) ·
[Web SDK changelog](https://github.com/opentdf/web-sdk/blob/main/CHANGELOG.md)

| Case | Planned acceptance |
| --- | --- |
| `NANO-01` | Parse the exact version, locator, policy, payload, and signature fields and recover the expected plaintext from both published examples. Test the key ID form separately with reference-peer fixtures. |
| `NANO-02` | Round-trip both ways with the pinned peer. Verify the policy binding, authenticated encryption, optional signature, and denied key release. |
| `NANO-03` | Test the 24-bit payload field's size boundaries including IV and tag overhead. Reject unknown versions, untrusted locators, truncated fields, and modified bindings, tags, or signatures without producing plaintext. |
