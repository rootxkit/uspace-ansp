package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

// Any environment value is refused with a field error naming a variable,
// or accepted; never a panic.
func FuzzLoadFrom(f *testing.F) {
	f.Add("ANSP_TOKEN_ISSUERS", "https://a.example=https://a.example/jwks")
	f.Add("ANSP_AUDIENCES", "ansp.example,ansp.lab")
	f.Add("ANSP_NATS_URL", "nats://u:p@h:4222")
	f.Add("ANSP_MTLS_MODE", "off")
	f.Fuzz(func(t *testing.T, name, value string) {
		if !strings.HasPrefix(name, Prefix) || strings.ContainsAny(name, "=") {
			name = "ANSP_TOKEN_ISSUERS"
		}
		_, err := LoadFrom([]string{"ANSP_PROCESS=api", name + "=" + value}, noFiles)
		if err == nil {
			return
		}
		for _, n := range fieldNames(err) {
			if !strings.HasPrefix(n, Prefix) {
				t.Fatalf("an error names %q", n)
			}
		}
		var fe *core.FieldError
		if !errors.As(err, &fe) {
			t.Fatalf("not a field error: %v", err)
		}
	})
}
