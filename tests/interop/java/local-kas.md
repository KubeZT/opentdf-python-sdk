# Local KAS for interoperability tests

Use Docker Compose, OpenSSL, and Go 1.26.10. Run this in a separate scratch
checkout of the platform.

```sh
smoke_dir="$(mktemp -d)"
project="opentdf-kas-smoke-$$"
git clone --depth 1 --branch service/v0.31.0 \
  https://github.com/opentdf/platform.git "$smoke_dir/platform"
cd "$smoke_dir/platform"
git rev-parse --short=7 HEAD  # 45a10ad
CGO_ENABLED=0 go build -o smoke-service ./service
```

Save this as `smoke-compose.yaml`. All published ports bind to loopback.
On Apple M4, set `JAVA_OPTS_APPEND=-XX:UseSVE=0` before starting Compose.

```yaml
services:
  keycloak:
    image: ghcr.io/opentdf/keycloak-standard:26.4.0
    command: [start-dev]
    environment:
      KC_HTTP_RELATIVE_PATH: /auth
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: changeme
      JAVA_OPTS_APPEND: "${JAVA_OPTS_APPEND:-}"
    ports:
      - "127.0.0.1:18888:8080"
  opentdfdb:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: changeme
      POSTGRES_DB: opentdf
    ports:
      - "127.0.0.1:15432:5432"
```

Copy `opentdf-dev.yaml` to `smoke-platform.yaml`. Add `db.port: 15432`,
set `server.host` to `127.0.0.1` and `server.port` to `18880`. Replace
`http://localhost:8080` with `http://localhost:18880` and
`http://localhost:8888` with `http://localhost:18888` throughout the file.
Leave the development keyring and `key_management: false` in place.

Copy `service/cmd/keycloak_data.yaml` to `smoke-keycloak.yaml` and make the
same URL replacements. Duplicate the `opentdf-sdk` client block for both `opentdf-denied` and
`opentdf-shared-reader`. Change each copy's `clientID` and `name`, keeping
the audience mapper, service account settings, and `opentdf-standard` role.
In the scratch checkout's `service/internal/fixtures/policy_fixtures.yaml`,
add `opentdf-shared-reader` to `subjectExternalValues` for
`subject_condition_sdk_client` alongside `opentdf-sdk`.

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kas-private.pem
openssl pkey -in kas-private.pem -pubout -out kas-cert.pem
openssl ecparam -name prime256v1 -genkey -noout -out kas-ec-private.pem
openssl req -new -x509 -key kas-ec-private.pem -subj /CN=kas \
  -days 1 -out kas-ec-cert.pem
docker compose -p "$project" -f smoke-compose.yaml up -d
```

When these probes pass, provision and start the platform in the same checkout:

```sh
docker compose -p "$project" -f smoke-compose.yaml exec -T opentdfdb \
  pg_isready -U postgres -d opentdf
curl -fsS -o /dev/null \
  http://localhost:18888/auth/realms/master/.well-known/openid-configuration

./smoke-service provision keycloak --endpoint http://localhost:18888/auth \
  --file smoke-keycloak.yaml
./smoke-service provision fixtures --config-file smoke-platform.yaml
./smoke-service start --config-file smoke-platform.yaml
```

Once `http://localhost:18880/healthz` reports `SERVING`, run the
[Java smoke test](README.md) in another terminal with these settings.

| Setting | Value |
| --- | --- |
| `OTDF_PLATFORM_URL`, `OTDF_KAS_URL` | `http://localhost:18880` |
| `OTDF_KAS_KEY_ID` | `r1` |
| `OTDF_ATTRIBUTE` | `https://example.com/attr/attr1/value/value1` |
| `OTDF_CLIENT_ID` for create and open | `opentdf-sdk` |
| `OTDF_CLIENT_ID` for denied open | `opentdf-denied` |
| `OTDF_CLIENT_SECRET` | Corresponding client secret in `smoke-keycloak.yaml` |

The updated policy fixture grants access to `opentdf-sdk` and
`opentdf-shared-reader`. The remaining client can authenticate and call
KAS, but has no matching subject mapping. For the [shared matrix](../README.md),
obtain a token per client at
`http://localhost:18888/auth/realms/opentdf/protocol/openid-connect/token`
using the OAuth client credentials grant.

Stop the platform with Ctrl-C, then remove this Compose project's containers
and volumes from the same shell.

```sh
docker compose -p "$project" -f smoke-compose.yaml down --volumes
```
