# Disconnected TDF access

Run `make test-federation` in either SDK checkout. It builds downstream
consumers from the Rust crate and Python wheel and starts isolated local
OpenTDF sites with separate identity providers and policy databases.

The test creates TDFs in both ZIP profiles before Site B exists. It stops
the producer's platform, IdP, and database and confirms their ports are
closed. An unenrolled site with different RSA and P-256 keys under the
same IDs cannot open those grants. The harness then provisions Site B with
the original trust-domain keys and local policy. Both SDKs open each original
archive at Site B, recover identical payload bytes, and verify the TDF's
SHA-256 digest is unchanged. A missing or wrong route, a token from Site A,
and an unentitled Site B token all fail without publishing plaintext. The
P-256 cases discover the KAS at Site B and fetch a client-credentials
token from Site B's issuer.

## Configure a trusted route

Configure the local KAS address and a token issued for that site's service.
Set the archive's logical KAS origin explicitly:

- Rust uses `KasConfig::new(local_kas, token)?.with_manifest_origin(origin)?`.
- Python passes `kas_url=local_kas`, `access_token=token`, and
  `manifest_kas_url=origin`.

The SDK writes the logical origin when creating a TDF. On read, the SDK
requires an exact match to the configured archive origin and sends rewrap
only to the configured endpoint. The signed request preserves the original
key access object. Existing callers use the endpoint as the archive origin.

Both sites use the same wrapping keys and key IDs. Enrollment copies
disposable RSA and P-256 keys between private temporary directories. In a
deployment, provisioning access to that key is a KAS operation. The SDKs
receive neither the wrapping private key nor the signing identity of the
producer. Sites that can use the same wrapping key share its compromise
boundary.

## Further federation cases

- Add an authorized grant for a different wrapping key and verify same-split
  failover with either KAS offline.
- Require distinct split IDs and verify access fails when a required KAS
  denies the request or is unreachable.
- Rotate wrapping keys and test access to old and new archives at sites
  enrolled before and after rotation. Exercise revocation during a partition
  and after reconnection.
