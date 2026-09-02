package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExpandProperties(t *testing.T) {
	t.Run("env plain", func(t *testing.T) {
		t.Setenv("MELLON_TEST_X", "hello")
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_X}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"hello"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("env with default used", func(t *testing.T) {
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_UNSET:fallback}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"fallback"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("env with default overridden", func(t *testing.T) {
		t.Setenv("MELLON_TEST_Y", "actual")
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_Y:fallback}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"actual"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("env missing no default", func(t *testing.T) {
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_MISSING}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `""` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("env empty value distinct from unset", func(t *testing.T) {
		t.Setenv("MELLON_TEST_EMPTY", "")
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_EMPTY:fallback}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `""` {
			t.Errorf("empty env should win over default, got %s", got)
		}
	})

	t.Run("sys plain", func(t *testing.T) {
		got, err := expandProperties([]byte(`"${sys.greeting}"`), map[string]string{"greeting": "hi"})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"hi"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("sys default", func(t *testing.T) {
		got, err := expandProperties([]byte(`"${sys.missing:def}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"def"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("json escape of quotes and backslashes", func(t *testing.T) {
		t.Setenv("MELLON_TEST_SPECIAL", `a"b\c`)
		raw := []byte(`{"k":"${env.MELLON_TEST_SPECIAL}"}`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]string
		if err := json.Unmarshal(got, &parsed); err != nil {
			t.Fatalf("output not valid JSON: %v (%s)", err, got)
		}
		if parsed["k"] != `a"b\c` {
			t.Errorf("round-trip mismatch: %q", parsed["k"])
		}
	})

	t.Run("newline in value stays valid json", func(t *testing.T) {
		t.Setenv("MELLON_TEST_NL", "line1\nline2")
		raw := []byte(`{"k":"${env.MELLON_TEST_NL}"}`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]string
		if err := json.Unmarshal(got, &parsed); err != nil {
			t.Fatalf("output not valid JSON: %v (%s)", err, got)
		}
		if parsed["k"] != "line1\nline2" {
			t.Errorf("round-trip mismatch: %q", parsed["k"])
		}
	})

	t.Run("multiple placeholders", func(t *testing.T) {
		t.Setenv("MELLON_TEST_A", "one")
		t.Setenv("MELLON_TEST_B", "two")
		got, err := expandProperties([]byte(`"${env.MELLON_TEST_A}-${env.MELLON_TEST_B}"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"one-two"` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("placeholder in numeric field", func(t *testing.T) {
		t.Setenv("MELLON_TEST_TTL", "600")
		raw := []byte(`{"ttl": ${env.MELLON_TEST_TTL}}`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]int
		if err := json.Unmarshal(got, &parsed); err != nil {
			t.Fatalf("output not valid JSON: %v (%s)", err, got)
		}
		if parsed["ttl"] != 600 {
			t.Errorf("got %d", parsed["ttl"])
		}
	})

	t.Run("unknown prefix left untouched", func(t *testing.T) {
		raw := []byte(`"${something.else}"`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), `${something.else}`) {
			t.Errorf("unknown prefix should pass through, got %s", got)
		}
	})

	t.Run("no prefix left untouched", func(t *testing.T) {
		raw := []byte(`"${bare}"`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), `${bare}`) {
			t.Errorf("bare token should pass through, got %s", got)
		}
	})

	t.Run("empty env key left untouched", func(t *testing.T) {
		raw := []byte(`"${env.}"`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), `${env.}`) {
			t.Errorf("empty key should pass through, got %s", got)
		}
	})

	t.Run("unterminated token left untouched", func(t *testing.T) {
		raw := []byte(`"${env.MISSING`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"${env.MISSING` {
			t.Errorf("got %s", got)
		}
	})

	t.Run("no placeholders passthrough", func(t *testing.T) {
		raw := []byte(`{"a":1,"b":"c"}`)
		got, err := expandProperties(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(raw) {
			t.Errorf("got %s", got)
		}
	})
}
