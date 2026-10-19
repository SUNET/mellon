package config

import (
	"reflect"
	"testing"
)

func TestClientAllowedOrigins(t *testing.T) {
	tests := []struct {
		name         string
		webOrigins   []string
		redirectURIs []string
		want         []string
	}{
		{
			name:       "exact origins",
			webOrigins: []string{"http://localhost:3000", "https://app.example.com"},
			want:       []string{"http://localhost:3000", "https://app.example.com"},
		},
		{
			name:       "trailing slash trimmed",
			webOrigins: []string{"http://localhost:3000/"},
			want:       []string{"http://localhost:3000"},
		},
		{
			name:         "plus expands redirect uris",
			webOrigins:   []string{"+"},
			redirectURIs: []string{"http://localhost:3000/callback", "https://app.example.com:8443/cb"},
			want:         []string{"http://localhost:3000", "https://app.example.com:8443"},
		},
		{
			name:         "plus with wildcard and relative redirect uris",
			webOrigins:   []string{"+"},
			redirectURIs: []string{"http://localhost:3000/*", "/relative/callback", "::bad"},
			want:         []string{"http://localhost:3000"},
		},
		{
			name:       "star kept",
			webOrigins: []string{"*"},
			want:       []string{"*"},
		},
		{
			name:         "dedupe",
			webOrigins:   []string{"http://localhost:3000", "+", "http://localhost:3000"},
			redirectURIs: []string{"http://localhost:3000/callback", "http://localhost:3000/other"},
			want:         []string{"http://localhost:3000"},
		},
		{
			name: "empty",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClientConfig{WebOrigins: tt.webOrigins, RedirectURIs: tt.redirectURIs}
			got := c.AllowedOrigins()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AllowedOrigins() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil client", func(t *testing.T) {
		var c *ClientConfig
		if got := c.AllowedOrigins(); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}
