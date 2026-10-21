package config

import (
	"bytes"
	"log"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// testdataDir holds real realm exports (see testdata/README.md).
const testdataDir = "../../testdata"

var logMu sync.Mutex

// loadTestdataWithLog loads testdata/<name> and returns the config together
// with everything Load logged.
func loadTestdataWithLog(t *testing.T, name string) (*Config, string) {
	t.Helper()
	logMu.Lock()
	defer logMu.Unlock()

	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()

	cfg, err := Load(filepath.Join(testdataDir, name), nil)
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return cfg, buf.String()
}

func loadTestdata(t *testing.T, name string) *Config {
	t.Helper()
	cfg, _ := loadTestdataWithLog(t, name)
	return cfg
}

func corpusFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(testdataDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no testdata realms found: %v", err)
	}
	for i, f := range files {
		files[i] = filepath.Base(f)
	}
	return files
}

// sameScopes compares scope lists as sets (nil and empty are equal).
func sameScopes(got, want []string) bool {
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) == 0 && len(w) == 0 {
		return true
	}
	return reflect.DeepEqual(g, w)
}

// TestCorpus_Invariants runs every realm in testdata through the scope
// engine and checks properties that must hold for any Keycloak realm.
func TestCorpus_Invariants(t *testing.T) {
	for _, name := range corpusFiles(t) {
		t.Run(name, func(t *testing.T) {
			cfg, logs := loadTestdataWithLog(t, name)

			// Real Keycloak exports reference only scopes they define
			// (possibly for another protocol, e.g. SAML role_list).
			if strings.Contains(logs, "undefined client scope") {
				t.Errorf("unexpected warnings:\n%s", logs)
			}

			for i := range cfg.Realm.Clients {
				c := &cfg.Realm.Clients[i]
				defaults := cfg.EffectiveDefaultScopes(c)
				optional := cfg.EffectiveOptionalScopes(c)

				granted, err := cfg.GrantScopes(c, "")
				if err != nil {
					t.Fatalf("%s: GrantScopes(\"\"): %v", c.ClientID, err)
				}
				if !sameScopes(granted, defaults) {
					t.Errorf("%s: empty request granted %v, want defaults %v", c.ClientID, granted, defaults)
				}

				all := append([]string{ScopeOpenID}, optional...)
				granted, err = cfg.GrantScopes(c, strings.Join(all, " "))
				if err != nil {
					t.Fatalf("%s: requesting all optional scopes: %v", c.ClientID, err)
				}
				if !sameScopes(granted, append(all, defaults...)) {
					t.Errorf("%s: granted %v, want openid + defaults + optional", c.ClientID, granted)
				}

				for _, s := range strings.Fields(cfg.TokenScope(granted)) {
					if s != ScopeOpenID && !cfg.FindClientScope(s).IncludeInTokenScope() {
						t.Errorf("%s: hidden scope %q in token scope", c.ClientID, s)
					}
				}

				if _, err := cfg.GrantScopes(c, "mellon-undefined-scope"); err == nil {
					t.Errorf("%s: undefined scope was granted", c.ClientID)
				}
			}
		})
	}
}

// Keycloak's own testsuite realm has no "clientScopes", so the built-in
// scopes apply. Audience mappers live on the clients.
func TestCorpus_KeycloakTestRealm(t *testing.T) {
	cfg := loadTestdata(t, "arquillian-testrealm.json")

	testApp := cfg.FindClient("test-app")
	if got := cfg.EffectiveDefaultScopes(testApp); !reflect.DeepEqual(got, builtinDefaultScopes) {
		t.Errorf("test-app defaults = %v, want built-ins", got)
	}
	if got := cfg.Audiences(testApp, nil, "access.token"); !reflect.DeepEqual(got, []string{"confidential-cli", "test-app"}) {
		t.Errorf("test-app aud = %v", got)
	}

	custom := cfg.FindClient("custom-audience")
	if got := cfg.EffectiveDefaultScopes(custom); !reflect.DeepEqual(got, []string{"web-origins", "profile", "email"}) {
		t.Errorf("custom-audience defaults = %v", got)
	}
	for _, target := range []string{"access.token", "id.token"} {
		if got := cfg.Audiences(custom, nil, target); !reflect.DeepEqual(got, []string{"foo-bar"}) {
			t.Errorf("custom-audience %s aud = %v", target, got)
		}
	}
	granted, err := cfg.GrantScopes(custom, "openid")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TokenScope(granted); got != "openid profile email" {
		t.Errorf("token scope = %q (web-origins must be hidden)", got)
	}
}

// The OIDF conformance realm defines its own clientScopes with
// include.in.token.scope=false on several, a SAML scope in the realm
// defaults, and plain-string user attributes.
func TestCorpus_ConformanceOIDC(t *testing.T) {
	cfg := loadTestdata(t, "conformance-oidc.json")
	c := cfg.FindClient("client1-oidcc-basic")

	granted, err := cfg.GrantScopes(c, "openid profile email")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"openid", "name_claims", "web-origins", "roles", "auth_time", "profile", "email"}
	if !reflect.DeepEqual(granted, want) {
		t.Errorf("granted = %v, want %v", granted, want)
	}
	if got := cfg.TokenScope(granted); got != "openid name_claims profile email" {
		t.Errorf("token scope = %q", got)
	}
	if got := cfg.Audiences(c, granted, "access.token"); !reflect.DeepEqual(got, []string{"resource-server"}) {
		t.Errorf("aud = %v", got)
	}

	// role_list is a SAML scope and must not apply to OIDC clients.
	if cfg.FindClientScope("role_list") != nil {
		t.Error("SAML scope role_list resolved as an OIDC scope")
	}

	john := cfg.FindUser("john")
	if john == nil {
		t.Fatal("user john missing")
	}
	for k, v := range map[string]string{
		"birthdate":           "2000-10-12",
		"phoneNumberVerified": "true",
		"updatedAt":           "1582521468",
	} {
		if got := john.Attributes[k]; !reflect.DeepEqual(got, []string{v}) {
			t.Errorf("john.%s = %v, want [%s]", k, got, v)
		}
	}
}

// The token-exchange realm hides most default scopes from the scope claim
// and uses included.client.audience mappers.
func TestCorpus_TokenExchange(t *testing.T) {
	cfg := loadTestdata(t, "token-exchange-v2.json")

	rc := cfg.FindClient("requester-client")
	granted, err := cfg.GrantScopes(rc, "")
	if err != nil {
		t.Fatal(err)
	}
	if !sameScopes(granted, []string{"service_account", "acr", "default-scope1", "roles", "basic"}) {
		t.Errorf("granted = %v", granted)
	}
	if got := cfg.TokenScope(granted); got != "default-scope1" {
		t.Errorf("token scope = %q", got)
	}
	if got := cfg.Audiences(rc, granted, "access.token"); !reflect.DeepEqual(got, []string{"requester-client"}) {
		t.Errorf("requester-client aud = %v", got)
	}

	if _, err := cfg.GrantScopes(cfg.FindClient("requester-client-2"), "profile"); err == nil {
		t.Error("requester-client-2 must not be granted profile")
	}

	sc := cfg.FindClient("subject-client")
	if got := cfg.Audiences(sc, nil, "access.token"); !reflect.DeepEqual(got, []string{"subject-client", "requester-client"}) {
		t.Errorf("subject-client aud = %v", got)
	}
	if got := cfg.Audiences(sc, nil, "id.token"); len(got) != 0 {
		t.Errorf("subject-client id aud = %v", got)
	}
}

// keycloak-nodejs-connect ships an array of realms in one file.
func TestCorpus_MultiRealmFile(t *testing.T) {
	cfg, logs := loadTestdataWithLog(t, "nodejs-test-realm.json")
	if cfg.Realm.Realm != "nodejs-test" {
		t.Errorf("realm = %q, want first non-master realm nodejs-test", cfg.Realm.Realm)
	}
	if !strings.Contains(logs, `file contains 3 realms [master nodejs-test tokenRealmTest]; serving "nodejs-test"`) {
		t.Errorf("logs = %q", logs)
	}
}
