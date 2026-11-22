# Testing

Run `make check` for the local suite. It covers file round trips, ZIP and
manifest validation, segment boundaries, and authenticated output. Run
the [interoperability matrix](../tests/interop/README.md) for live KAS tests.

| Reference | Pin |
| --- | --- |
| [TDF specification tag](https://github.com/opentdf/spec/releases/tag/4.3.0) | `4.3.0` (`c6592ba`) |
| [Java SDK](https://github.com/opentdf/java-sdk/releases/tag/v0.19.1) | `0.19.1` (`8e6f8bc`) |
| [Go SDK](https://github.com/opentdf/platform/releases/tag/sdk%2Fv0.35.0) | `v0.35.0` (`b048476`) |
| [OpenTDF Platform](https://github.com/opentdf/platform/releases/tag/service/v0.31.0) | `service/v0.31.0` (`45a10ad`) |

## ZIP profiles

| Writer profile | ZIP manifest | Version field | HS256 policy-binding digest before Base64 |
| --- | --- | --- | --- |
| Java-compatible (default) | `0.manifest.json` | Root `schemaVersion` | Lowercase hexadecimal |
| Spec ZIP (explicit) | `manifest.json` | `payload.tdf_spec_version` | Raw digest bytes |

The profiles cover a single RSA KAS grant, a single policy attribute, and
payloads up to 64 MiB. Both write `0.payload`. Spec ZIP readers also resolve
safe, flat payload member names from the manifest. Go 0.35.0 writes the
Java-compatible layout and can read both layouts with `0.payload`. Java
0.19.1 expects the Java-compatible layout.

The spec tag's own VERSION file reads `4.2.0`. The spec ZIP profile uses
the manifest placement and binding encoding described by the pinned tag
with version value `4.3.0`, as used by the pinned SDKs. The profile is a
tested subset of base TDF.

| Area | Shared check |
| --- | --- |
| Container | Exactly two stored members, matching profile and version field, one grant, and a valid payload reference. |
| Integrity | Equal bytes across segment boundaries. Reject ciphertext tampering and leave the destination absent. |
| Key access | Allow two entitled identities on the same KAS. Reject invalid credentials, unentitled identities, and unreachable KAS. |

Record the revision, license, and checksum of any fixture brought in from
the [upstream suite](https://github.com/opentdf/tests). Keep credentials and
generated private keys out of fixtures. KubeZT supplies its own package as
payload bytes and owns the `.kube` extension.
