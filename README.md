# mellon

> "Speak friend, and enter."

A lightweight OpenID Connect Provider (OP) written in Go, intended for **integration testing and local development**. It is configuration-compliant with [Keycloak](https://www.keycloak.org/), making it a drop-in replacement in test environments where running a full Keycloak instance is impractical.

> **Not for production use.** This provider stores credentials in plaintext and has no persistence. Use it in CI pipelines, testcontainers, and local dev setups.

## Keycloak Compatibility

This service uses the same realm configuration format as Keycloak, including:

- **Realm JSON import** — configure clients, users, roles, and credentials using Keycloak's `realm.json` format.
- **Protocol Mappers** — supports `oidc-usermodel-attribute-mapper` for mapping arbitrary user attributes to token claims (ID token, access token, and userinfo).
- **Endpoint layout** — discovery, token, userinfo, JWKS, introspection, and logout endpoints follow Keycloak's `/realms/{realm}/protocol/openid-connect/` URL structure.

## Endpoints

| Endpoint      | Path                                                            |
| ------------- | --------------------------------------------------------------- |
| Discovery     | `GET /realms/{realm}/.well-known/openid-configuration`          |
| Authorization | `GET /realms/{realm}/protocol/openid-connect/auth`              |
| Token         | `POST /realms/{realm}/protocol/openid-connect/token`            |
| UserInfo      | `GET /realms/{realm}/protocol/openid-connect/userinfo`          |
| JWKS          | `GET /realms/{realm}/protocol/openid-connect/certs`             |
| Introspection | `POST /realms/{realm}/protocol/openid-connect/token/introspect` |
| Logout        | `GET /realms/{realm}/protocol/openid-connect/logout`            |

## Supported Features

- Authorization Code flow (with PKCE)
- Client Credentials flow
- Resource Owner Password grant (direct access) — enables fully headless operation
- Refresh Token flow
- JWT signing with RS256, ES256, and EdDSA
- Token introspection
- Configurable protocol mappers for custom claims

## Headless / Testcontainer Usage

This service can run fully headless with no browser interaction required. Use the **client_credentials** grant for service-to-service auth, or the **password** grant for user authentication:

```sh
# Client credentials (no user)
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=test-client&client_secret=test-secret"

# Password grant (user auth without browser)
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -d "grant_type=password&client_id=test-client&client_secret=test-secret&username=testuser&password=password&scope=openid"
```

Set `"directAccessGrantsEnabled": true` on the client in `realm.json` to enable the password grant.

## Configuration

Configure the service using a Keycloak-compatible `realm.json` file. See [realm.json](realm.json) for an example.

## Development

```sh
make start    # start with docker-compose
make stop     # stop services
make restart  # restart services
```

### Run tests

```sh
go test ./...
```
