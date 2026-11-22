# Java interoperability driver

Requires JDK 17 and Maven. The driver uses OpenTDF Java SDK 0.19.1.

Use the [local KAS setup](local-kas.md) for the platform and test identities. Set `OTDF_PLATFORM_URL`,
`OTDF_KAS_URL`, `OTDF_CLIENT_ID`, and `OTDF_CLIENT_SECRET` in the environment.
For HTTPS with a local CA, set `OTDF_TRUST_CERT_DIR` to the directory
containing its certificate. HTTP URLs must use loopback hosts.

Set `OTDF_ATTRIBUTE` to the policy attribute value FQN before creating a TDF.
Set `OTDF_KAS_KEY_ID` when choosing a specific RSA key on the KAS.

```sh
mvn -q compile exec:java -Dexec.args='create input.bin payload.tdf'
mvn -q compile exec:java -Dexec.args='open payload.tdf recovered.bin'
cmp input.bin recovered.bin
unzip -Z1 payload.tdf
```

Switch the client ID and secret to an identity with no entitlement to the
attribute, then check the same TDF:

```sh
mvn -q compile exec:java -Dexec.args='expect-denied payload.tdf denied.bin'
test ! -e denied.bin
```

`expect-denied` requires a KAS `permission_denied` response.

## Baseline

OpenTDF Java SDK 0.19.1 with Platform service/v0.31.0 wrote two stored ZIP
entries in this order:

```text
0.payload
0.manifest.json
```

The manifest declared schema 4.3.0 and referenced `0.payload`. The entitled
client recovered the input byte for byte. KAS denied the second client with
`permission_denied` and logged `policy_denied`. The denied read produced no
output file.
