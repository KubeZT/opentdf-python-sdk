# KAS test cases

The live matrix uses separate authenticated identities against one KAS.
A producer writes the archive, a second entitled identity opens it, and
an unentitled identity gets denied. The current readers reject archives
with multiple grants before attempting key access.

## Producer-independent consumption

Create a TDF against a published wrapping key for a trust domain. The
producer has no consumer roster, site URL, or per-site public key.
After creation, provision Site B as a member of that domain. Site B must
authorize and open the original, byte-identical archive using only local
services with the producer's KAS and identity provider unreachable.
Repeat with an unprovisioned site, a wrong key for the same key ID, and a
valid identity without the attribute. All must leave the output absent.

Test key rotation with artifacts written before and after the change,
and test a newly enrolled site's access to each generation. Document how
any shared private-key capability is provisioned, scoped, and revoked.
Separate signature trust and payload decryption in the test assertions.
Test a stable KAS identifier for the trust domain that resolves to a
locally configured endpoint. Require a trusted mapping and a token for
the local endpoint's audience. Capture requests to prove the consumer
never contacted the producer's services.

## Two-site acceptance cases

Provision Site A and Site B with distinct KAS keys and IDs. Give each
site a local issuer, policy configuration, and entitled and unentitled
test identities. Use peer-produced artifacts to test each SDK.

| Case | Expected outcome |
| --- | --- |
| A-origin archive with a grant only for A, B trusts A's signing identity | B can verify provenance where signatures are supported. Decryption at B requires authorized key access from A or a new grant B can unwrap. |
| A-origin archive with a grant added for B before disconnect, both grants refer to the same split ID | With A unreachable, B can open the archive through its local KAS. A caller without B's entitlement is denied. |
| Two distinct required split IDs | Both authorized shares are needed. An unavailable or denied KAS prevents opening. |
| Unknown KAS, wrong issuer or token audience, or modified policy binding | Reject access and leave the output absent. Never send a site's credential to an untrusted endpoint. |
| Rotation and revocation during a partition | Verify the results before and after a local update and after reconnection. Record the time each site can enforce the change. |

For each disconnected case, block the A endpoint and prove the SDK contacts
only B. Test adding B's grant to an existing artifact through an authorized
key-transfer workflow as well as provisioning both grants during creation.
The [pinned Go reader](https://github.com/opentdf/platform/blob/sdk/v0.35.0/sdk/tdf.go)
uses one successful grant per split ID and requires every distinct split.
