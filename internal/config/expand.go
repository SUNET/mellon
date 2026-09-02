package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// expandProperties replaces Keycloak-style ${env.NAME} and ${sys.NAME}
// placeholders (with optional ":default") in a raw realm-import document.
// Substituted values are JSON-escaped so quotes/backslashes/newlines from
// env values cannot break the JSON stream. Unknown prefixes are left
// untouched so future Keycloak features degrade to a parse-time error
// instead of silently blanking.
func expandProperties(data []byte, sys map[string]string) ([]byte, error) {
	var out strings.Builder
	out.Grow(len(data))

	s := string(data)
	for i := 0; i < len(s); {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			out.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			out.WriteString(s[i:])
			break
		}
		token := s[i+2 : i+2+end]
		replacement, ok := resolveToken(token, sys)
		if !ok {
			out.WriteString(s[i : i+2+end+1])
			i += 2 + end + 1
			continue
		}
		escaped, err := jsonEscape(replacement)
		if err != nil {
			return nil, fmt.Errorf("escape value for ${%s}: %w", token, err)
		}
		out.WriteString(escaped)
		i += 2 + end + 1
	}
	return []byte(out.String()), nil
}

// resolveToken interprets the inside of a ${...} placeholder. It returns
// (value, true) when the prefix is recognised, or ("", false) to signal
// that the caller should leave the placeholder untouched.
func resolveToken(token string, sys map[string]string) (string, bool) {
	name, def, hasDef := splitDefault(token)

	var prefix, key string
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		prefix = name[:dot]
		key = name[dot+1:]
	}

	switch prefix {
	case "env":
		if key == "" {
			return "", false
		}
		if v, ok := os.LookupEnv(key); ok {
			return v, true
		}
		if hasDef {
			return def, true
		}
		log.Printf("config: ${env.%s} not set and no default; using empty string", key)
		return "", true
	case "sys":
		if key == "" {
			return "", false
		}
		if v, ok := sys[key]; ok {
			return v, true
		}
		if hasDef {
			return def, true
		}
		log.Printf("config: ${sys.%s} not set and no default; using empty string", key)
		return "", true
	default:
		return "", false
	}
}

// splitDefault splits "name:default" into ("name", "default", true).
// A missing colon returns ("name", "", false).
func splitDefault(token string) (string, string, bool) {
	if i := strings.IndexByte(token, ':'); i >= 0 {
		return token[:i], token[i+1:], true
	}
	return token, "", false
}

// jsonEscape returns v encoded as JSON string content (no surrounding quotes),
// suitable for splicing back into a JSON document.
func jsonEscape(v string) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return "", fmt.Errorf("unexpected json.Marshal output: %s", b)
	}
	return string(b[1 : len(b)-1]), nil
}
