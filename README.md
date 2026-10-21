# mellon

> "Speak friend, and enter."

A lightweight OpenID Connect Provider (OP) written in Go, intended for **integration testing and local development**. It is configuration-compliant with [Keycloak](https://www.keycloak.org/), making it a drop-in replacement in test environments where running a full Keycloak instance is impractical.

> **Not for production use.** This provider stores credentials in plaintext and has no persistence. Use it in CI pipelines, testcontainers, and local dev setups.

## Keycloak Compatibility

This service uses the same realm configuration format as Keycloak, including:

- **Realm JSON import** — configure clients, users, roles, and credentials using Keycloak's `realm.json` format.
- **Client scopes** — realm `clientScopes` and per-client `defaultClientScopes` / `optionalClientScopes`, enforced the way Keycloak does (see [Client scopes](#client-scopes)).
- **Protocol Mappers** — on clients and on client scopes:
  - `oidc-usermodel-attribute-mapper` maps arbitrary user attributes to token claims (ID token, access token, and userinfo).
  - `oidc-audience-mapper` adds an audience (`included.client.audience` or `included.custom.audience`) to the access and/or ID token `aud`.
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
- Keycloak-style client scope enforcement (default / optional scopes, `invalid_scope`)
- Configurable protocol mappers for custom claims and audiences
- CORS for browser-based clients, driven by each client's `webOrigins`

## CORS

Browser-based clients (e.g. SPAs doing Authorization Code + PKCE) can call the token and userinfo endpoints cross-origin. Allowed origins come from the client's `webOrigins` in `realm.json`, with Keycloak semantics:

- `"https://app.example.com"` — exact origin match.
- `"+"` — the origins (`scheme://host[:port]`) of all the client's `redirectUris`.
- `"*"` — any origin.

| Endpoint                         | CORS behaviour                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------ |
| `token`                          | Origin must be in the calling client's `webOrigins` (applies to error responses too).            |
| `userinfo`                       | Origin must be in the access token's `allowed-origins` claim. 401 responses are readable by any origin. |
| `certs`, discovery               | Any origin.                                                                                      |
| `auth`, `login`, `logout`, `token/introspect` | No CORS headers (page loads or server-to-server).                                   |

Access tokens carry an `allowed-origins` claim, as Keycloak's do. `OPTIONS` preflight requests on the CORS-enabled endpoints return `204` with `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers: Authorization, Content-Type` and `Access-Control-Max-Age: 3600`; as in Keycloak, the preflight itself is permissive and the actual request enforces the origin. The allowed origin is always echoed (never a literal `*`), `Vary: Origin` is set, and `Access-Control-Allow-Credentials` is not sent.

## Client scopes

Granted scopes follow Keycloak:

- All of the client's **default** client scopes are always granted, whether requested or not.
- **Optional** client scopes are granted only when requested in `scope`.
- `openid` is not a client scope. It is granted (and an ID token issued) only when requested; listing it in `defaultClientScopes` has no effect.
- Requesting any other scope fails with `invalid_scope` (`400` from the token endpoint; a redirect with `error=invalid_scope` from the authorization endpoint).
- On `refresh_token`, `scope` may narrow the original grant but not widen it.

Which scopes exist:

- If `realm.json` has no `clientScopes`, Keycloak's built-ins are used: `profile`, `email`, `roles`, `web-origins`, `acr`, `basic` (default) and `offline_access`, `phone`, `address`, `microprofile-jwt` (optional).
- If `clientScopes` is present, **only** those scopes exist. References to undefined scopes are logged as a warning at startup and ignored, just like a Keycloak import. Remember to define `profile`/`email` yourself if clients use them.
- A client that omits `defaultClientScopes` / `optionalClientScopes` inherits the realm's `defaultDefaultClientScopes` / `defaultOptionalClientScopes` (or the built-ins). An explicit `[]` means none.

Token contents:

- The `scope` claim lists `openid` plus the granted scopes, except those with the attribute `"include.in.token.scope": "false"` (by default `roles`, `web-origins`, `acr` and `basic`).
- `name`, `given_name`, `family_name` and `preferred_username` are only included with `profile`; `email` and `email_verified` only with `email`.
- Protocol mappers of the client **and** of every granted client scope are applied.
- Access tokens carry `typ: "Bearer"` and `azp: <client_id>`. As in Keycloak, `aud` contains only the audiences added by audience mappers, and is omitted when there are none. ID tokens always have the client as `aud` (`typ: "ID"`).
- `client_credentials` does not return a refresh token.

### Audience

To make tokens for an API carry `aud: "my-api"`, add an audience mapper, either to the client or to a client scope (then only tokens that were granted the scope get the audience):

```json
{
  "clientScopes": [
    {
      "name": "my-api.read",
      "protocol": "openid-connect",
      "protocolMappers": [
        {
          "name": "aud-my-api",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.custom.audience": "my-api",
            "access.token.claim": "true",
            "id.token.claim": "false"
          }
        }
      ]
    }
  ],
  "clients": [
    {
      "clientId": "svc",
      "secret": "svc-secret",
      "serviceAccountsEnabled": true,
      "defaultClientScopes": ["my-api.read"]
    }
  ]
}
```

A single audience is serialized as a string (`"aud": "my-api"`), several as an array. Token introspection also returns `aud`, `azp` and `typ`.

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

## TLS

mellon serves HTTPS on `8443` (`KC_HTTPS_PORT` / `-https-port`). The certificate is chosen in this order:

1. **Explicit files** — set via env or flag (Keycloak-compatible names):

   | Env                             | Flag                          |
   | ------------------------------- | ----------------------------- |
   | `KC_HTTPS_CERTIFICATE_FILE`     | `-https-certificate-file`     |
   | `KC_HTTPS_CERTIFICATE_KEY_FILE` | `-https-certificate-key-file` |

   Both must be set and must load, otherwise mellon exits with an error.

2. **Default mount paths** — if nothing is set explicitly, mellon looks for
   `/opt/keycloak/conf/server.crt.pem` and `/opt/keycloak/conf/server.key.pem`.
   If only one exists or the pair fails to load, a warning is logged and mellon falls back to (3).

3. **Self-signed** — a fresh P-256 certificate (CN `mellon`) with SANs `localhost`, `127.0.0.1`, `::1` and the host from `KC_HOSTNAME_URL`.

Files are PEM; the certificate file may contain a full chain (leaf first). The chosen source is logged at startup (`HTTPS certificate: ...`).

```yaml
services:
  mellon:
    image: docker.sunet.se/iam_vc/mellon:latest
    volumes:
      - ./realm.json:/opt/keycloak/data/import/realm.json:ro
      - ./certs:/opt/keycloak/conf:ro   # server.crt.pem + server.key.pem
```

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
