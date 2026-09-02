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

### Property substitution

`realm.json` supports Keycloak-style `${...}` placeholders that are expanded before the file is parsed. This lets you keep secrets and per-environment values out of the checked-in JSON, and keeps the file portable back to a real Keycloak container.

| Syntax                       | Source                                    |
| ---------------------------- | ----------------------------------------- |
| `${env.NAME}`                | environment variable `NAME`               |
| `${env.NAME:default}`        | environment variable, with fallback       |
| `${sys.NAME}`                | system property `NAME` (see below)        |
| `${sys.NAME:default}`        | system property, with fallback            |

Example:

```json
{
  "realm": "demo",
  "users": [
    {
      "username": "demo",
      "credentials": [
        { "type": "password", "value": "${env.DEMO_USER_PASSWORD}" }
      ]
    }
  ]
}
```

System properties are supplied on the command line, Java-style, or via the `KC_SYS_PROPS` environment variable (comma-separated `k=v` pairs):

```sh
mellon -import-realm ./realm.json -D greeting=hello -D tier=dev
KC_SYS_PROPS="greeting=hello,tier=dev" mellon -import-realm ./realm.json
```

Notes:

- If a placeholder resolves to a missing variable with no default, it becomes an empty string and mellon logs a warning.
- Substituted values are JSON-escaped, so env values containing `"`, `\`, or newlines won't break parsing. (This is a small, safe divergence from Keycloak's raw text substitution.)
- Unknown prefixes (e.g. `${vault.foo}`) are left untouched. Inside a quoted JSON string they load literally, so you can spot them in the parsed config; outside a quoted string they will usually cause a JSON parse error.
- Because expansion happens on the raw bytes before JSON parsing, placeholders may appear in numeric fields too: `"accessTokenLifespan": ${env.KC_TTL:300}`.

## Docker Image

Prebuilt images are published to SUNET's registry at `docker.sunet.se/iam_vc/mellon`.

```sh
docker pull docker.sunet.se/iam_vc/mellon:latest
```

Available tags:

- `latest` — points to the most recent semver release.
- `vX.Y.Z` — immutable tag for a specific release. Pin to one of these (e.g. in CI or testcontainers) when you need reproducible builds.

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
