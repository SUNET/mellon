# testdata

Unmodified Keycloak realm files from Keycloak's own repositories. They are the reference for how mellon interprets a realm: when mellon and these files disagree, mellon is wrong.

The tests in `internal/config` and `internal/oidc` load all of them. Adding a file here adds it to `TestCorpus_Invariants` automatically.

| File | Source (commit) | License |
| ---- | --------------- | ------- |
| `arquillian-testrealm.json` | [keycloak/keycloak](https://github.com/keycloak/keycloak) `testsuite/integration-arquillian/tests/base/src/test/resources/testrealm.json` (`b2544d7b3011`) | Apache-2.0 |
| `tests-testrealm.json` | keycloak/keycloak `tests/base/src/test/resources/org/keycloak/tests/testrealm.json` (`b2544d7b3011`) | Apache-2.0 |
| `export-singlefile.json` | keycloak/keycloak `testsuite/model/src/test/resources/exportimport/singleFile/testrealm.json` (`b2544d7b3011`) | Apache-2.0 |
| `migration-13.0.1.json` | keycloak/keycloak `tests/base/src/test/resources/org/keycloak/tests/migration/migration-realm-13.0.1-client-policies-test.json` (`b2544d7b3011`) | Apache-2.0 |
| `token-exchange-v2.json` | keycloak/keycloak `testsuite/integration-arquillian/tests/base/src/test/resources/token-exchange/testrealm-token-exchange-v2.json` (`b2544d7b3011`) | Apache-2.0 |
| `conformance-oidc.json` | [keycloak/keycloak-oauth-sig](https://github.com/keycloak/keycloak-oauth-sig) `conformance-tests-env/test-target/keycloak/keycloak/realms/realm-oidc.json` (`8c2e07a8b267`) | Apache-2.0 |
| `conformance-fapi2-sp-final.json` | keycloak/keycloak-oauth-sig `conformance-tests-env/test-target/keycloak/keycloak/realms/realm-fapi2-sp-final.json` (`8c2e07a8b267`) | Apache-2.0 |
| `nodejs-test-realm.json` | [keycloak/keycloak-nodejs-connect](https://github.com/keycloak/keycloak-nodejs-connect) `test/fixtures/auth-utils/nodejs-test-realm.json` (`b50534c40bbd`) | Apache-2.0 |
| `playground-oid4vci.json` | [keycloak/keycloak-playground](https://github.com/keycloak/keycloak-playground) `fapi-playground/oid4vci/singleFile-realm.json` (`a4a6e4317cb9`) | Apache-2.0 |
| `client-testrealm.json` | [keycloak/keycloak-client](https://github.com/keycloak/keycloak-client) `testsuite/admin-client-tests/src/test/resources/testrealm.json` (`88d55adee456`) | Apache-2.0 |
