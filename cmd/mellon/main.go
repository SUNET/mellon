package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/server"
	"github.com/masv3971/mellon/internal/session"
)

func main() {
	configPath := flag.String("import-realm", envOrDefault("KC_IMPORT_REALM", "/opt/keycloak/data/import/realm.json"), "path to realm.json config file")
	httpAddr := flag.String("http-port", ":"+envOrDefault("KC_HTTP_PORT", "8080"), "HTTP listen address")
	httpsAddr := flag.String("https-port", ":"+envOrDefault("KC_HTTPS_PORT", "8443"), "HTTPS listen address")
	issuer := flag.String("hostname", envOrDefault("KC_HOSTNAME_URL", "http://localhost:8080"), "issuer base URL")

	sysProps := parseSysProps(os.Getenv("KC_SYS_PROPS"))
	flag.Func("D", "system property for realm.json ${sys.*} expansion (repeatable: -D key=value)", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return fmt.Errorf("expected key=value, got %q", s)
		}
		sysProps[k] = v
		return nil
	})
	flag.Parse()

	cfg, err := config.Load(*configPath, sysProps)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg.Issuer = *issuer

	kid := uuid.New().String()[:8]
	var kp *opcrypto.KeyPair

	if cfg.Realm.PrivateKey != "" {
		kp, err = opcrypto.LoadRSAPrivateKeyFromPEM(cfg.Realm.PrivateKey, kid)
		if err != nil {
			log.Fatalf("Failed to load private key from config: %v", err)
		}
		log.Printf("Loaded signing key from config (algorithm: %s, kid: %s)", kp.Algorithm, kp.KID)
	} else {
		alg := cfg.GetAlgorithm()
		kp, err = opcrypto.GenerateKeyPair(alg, kid)
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}
		log.Printf("Generated signing key (algorithm: %s, kid: %s)", alg, kid)
	}

	store := session.NewStore()
	router := server.NewRouter(cfg, kp, store)

	log.Printf("OIDC Provider starting for realm %q", cfg.Realm.Realm)
	log.Printf("Discovery: %s/realms/%s/.well-known/openid-configuration", cfg.Issuer, cfg.Realm.Realm)

	srv := server.New(router)
	if err := srv.Start(*httpAddr, *httpsAddr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseSysProps parses "k1=v1,k2=v2" (blanks tolerated) into a map for
// ${sys.*} substitution. Entries without '=' are skipped with a warning.
func parseSysProps(raw string) map[string]string {
	m := make(map[string]string)
	if raw == "" {
		return m
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k == "" {
			log.Printf("KC_SYS_PROPS: skipping malformed entry %q", entry)
			continue
		}
		m[k] = v
	}
	return m
}
