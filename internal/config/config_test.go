package config

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

func env(kv map[string]string) []string {
	out := []string{"PATH=/bin", "ANSP_PROCESS=api"}
	for k, v := range kv {
		out = append(out, k+"="+v)
	}
	return out
}

func noFiles(string) ([]byte, error) { return nil, fs.ErrNotExist }

// fieldNames lists the variables named by a joined error, in order.
func fieldNames(err error) []string {
	var out []string
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, e := range joined.Unwrap() {
			out = append(out, fieldNames(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		out = append(out, fe.Field)
	}
	return out
}

func TestLoadDefaults(t *testing.T) {
	c, err := LoadFrom(env(nil), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.Process != ProcessAPI || c.Instance != "local" || c.SystemID != "ansp" || c.HTTPAddr != ":8080" ||
		c.ClientID != "ansp-01" || c.MTLSMode != MTLSRequired || c.LogLevel != "info" || c.Country != "GEO" {
		t.Fatalf("defaults %+v", c)
	}
	if c.DBMaxConns != 10 || c.DBAcquireTimeoutS != 5 || c.DBStatementTimeoutS != 5 || c.DBTxTimeoutS != 15 {
		t.Fatalf("database bounds %+v", c)
	}
	if c.NATSURL != "" || c.Audiences != nil || c.TokenIssuers != nil || c.ClientSecret != "" {
		t.Fatalf("unset values %+v", c)
	}
}

func TestLoadEveryVariable(t *testing.T) {
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/client" {
			return []byte("s3cret\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	c, err := LoadFrom(env(map[string]string{
		"ANSP_PROCESS":                       "manned-feed",
		"ANSP_INSTANCE":                      "feed-1",
		"ANSP_AUDIENCES":                     "ansp.example, ansp.lab",
		"ANSP_HTTP_ADDR":                     "127.0.0.1:9000",
		"ANSP_NATS_URL":                      "nats://feed:pw@nats:4222",
		"ANSP_NATS_CREDS":                    "/run/nats/feed.creds",
		"ANSP_RELATIONAL_DSN":                "postgres://api:pw@db:5432/ansp?sslmode=disable",
		"ANSP_TIMESERIES_DSN":                "postgres://tsdb:pw@db:5432/ansp_ts?sslmode=disable&password=pw",
		"ANSP_TOKEN_ISSUERS":                 "https://auth.example=https://auth.example/jwks,https://lab.example=https://lab.example/jwks",
		"ANSP_TOKEN_URL":                     "https://auth.example/oauth/token",
		"ANSP_CLIENT_SECRET_FILE":            "/run/secrets/client",
		"ANSP_CISP_URL":                      "https://cisp.example",
		"ANSP_CIS_NOTIFY_ISSUERS":            "https://cisp.example=https://cisp.example/jwks",
		"ANSP_DSS_URL":                       "https://dss.example",
		"ANSP_AUTHORITY_URL":                 "https://authority.example",
		"ANSP_PUBLIC_BASE_URL":               "https://ansp.example",
		"ANSP_MTLS_MODE":                     "off",
		"ANSP_LOG_LEVEL":                     "debug",
		"ANSP_OTLP_ENDPOINT":                 "http://otel:4318",
		"ANSP_COUNTRY":                       "GEO",
		"ANSP_DB_MAX_CONNS":                  "20",
		"ANSP_DB_TX_TIMEOUT_S":               "30",
		"ANSP_MTLS_BINDINGS_FILE":            "/run/secrets/bindings.json",
		"ANSP_TRUSTED_PROXIES":               "10.0.0.0/8, 192.0.2.10",
		"ANSP_WS_ALLOWED_ORIGINS":            "https://ansp.example, http://localhost:3000",
		"ANSP_SESSION_KEY_FILE":              "/run/secrets/session.pem",
		"ANSP_SECRETS_KEY_FILE":              "/run/secrets/secrets.key",
		"ANSP_LOGIN_IP_PER_MIN":              "20",
		"ANSP_LOGIN_USER_PER_MIN":            "3",
		"ANSP_LOGIN_LOCKOUT_AFTER":           "5",
		"ANSP_LOGIN_LOCKOUT_S":               "600",
		"ANSP_BOOTSTRAP_ADMIN_USERNAME":      "root",
		"ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE": "/run/secrets/admin",
	}), files)
	if err != nil {
		t.Fatal(err)
	}
	if c.Process != ProcessMannedFeed || !slices.Equal(c.Audiences, []string{"ansp.example", "ansp.lab"}) ||
		len(c.TokenIssuers) != 2 || c.TokenIssuers[1].JWKSURL != "https://lab.example/jwks" ||
		c.CISNotifyIssuers[0].Issuer != "https://cisp.example" || c.ClientSecret != "s3cret" || c.MTLSMode != MTLSOff ||
		c.DBMaxConns != 20 || c.DBTxTimeoutS != 30 {
		t.Fatalf("loaded %+v", c)
	}
	if !slices.Equal(c.TrustedProxies, []string{"10.0.0.0/8", "192.0.2.10"}) || len(c.WSAllowedOrigins) != 2 ||
		c.SessionKeyFile != "/run/secrets/session.pem" || c.SecretsKeyFile != "/run/secrets/secrets.key" ||
		c.MTLSBindingsFile != "/run/secrets/bindings.json" || c.LoginIPPerMin != 20 || c.LoginUserPerMin != 3 ||
		c.LoginLockoutAfter != 5 || c.LoginLockoutS != 600 || c.BootstrapAdminUsername != "root" {
		t.Fatalf("auth variables %+v", c)
	}
	r := c.Redacted()
	if r["ANSP_NATS_URL"] != "nats://***@nats:4222" ||
		r["ANSP_RELATIONAL_DSN"] != "postgres://***@db:5432/ansp?sslmode=disable" ||
		!strings.Contains(r["ANSP_TIMESERIES_DSN"], "password=***") ||
		r["ANSP_CLIENT_SECRET_FILE"] != "/run/secrets/client" || r["ANSP_DB_MAX_CONNS"] != "20" {
		t.Fatalf("redacted %v", r)
	}
	for k, v := range r {
		if strings.Contains(v, "pw") || strings.Contains(v, "s3cret") {
			t.Fatalf("%s leaks a secret: %q", k, v)
		}
	}
	if len(r) != len(c.RedactedNames()) {
		t.Fatalf("redacted has %d names, RedactedNames %d", len(r), len(c.RedactedNames()))
	}
}

// Every problem is reported at once and names its variable.
func TestLoadRefusesNamingTheVariable(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"unknown variable", map[string]string{"ANSP_MIGRATE_ON_START": "true", "ANSP_DSS_AUDIENCE": "dss"}, []string{"ANSP_DSS_AUDIENCE", "ANSP_MIGRATE_ON_START"}},
		{"process missing", map[string]string{"ANSP_PROCESS": ""}, []string{"ANSP_PROCESS"}},
		{"process unknown", map[string]string{"ANSP_PROCESS": "worker"}, []string{"ANSP_PROCESS"}},
		{"mtls mode", map[string]string{"ANSP_MTLS_MODE": "optional"}, []string{"ANSP_MTLS_MODE"}},
		{"log level", map[string]string{"ANSP_LOG_LEVEL": "trace"}, []string{"ANSP_LOG_LEVEL"}},
		{"relative url", map[string]string{"ANSP_DSS_URL": "dss.example"}, []string{"ANSP_DSS_URL"}},
		{"bad url", map[string]string{"ANSP_NATS_URL": "nats://a b:%zz@x"}, []string{"ANSP_NATS_URL"}},
		{"issuer pair", map[string]string{"ANSP_TOKEN_ISSUERS": "https://auth.example"}, []string{"ANSP_TOKEN_ISSUERS"}},
		{"issuer twice", map[string]string{"ANSP_CIS_NOTIFY_ISSUERS": "https://c.example=https://c.example/j,https://c.example=https://c.example/k"}, []string{"ANSP_CIS_NOTIFY_ISSUERS"}},
		{"issuer jwks", map[string]string{"ANSP_TOKEN_ISSUERS": "https://auth.example=/jwks"}, []string{"ANSP_TOKEN_ISSUERS"}},
		{"issuer not a URL", map[string]string{"ANSP_TOKEN_ISSUERS": "authority=https://auth.example/jwks"}, []string{"ANSP_TOKEN_ISSUERS"}},
		{"audience with scheme", map[string]string{"ANSP_AUDIENCES": "https://ansp.example"}, []string{"ANSP_AUDIENCES"}},
		{"system id as audience", map[string]string{"ANSP_AUDIENCES": "ansp"}, []string{"ANSP_AUDIENCES"}},
		{"public host not an audience", map[string]string{"ANSP_AUDIENCES": "ansp.lab", "ANSP_PUBLIC_BASE_URL": "https://ansp.example"}, []string{"ANSP_AUDIENCES"}},
		{"one database for two trees", map[string]string{"ANSP_RELATIONAL_DSN": "postgres://db/ansp", "ANSP_TIMESERIES_DSN": "postgres://db/ansp"}, []string{"ANSP_TIMESERIES_DSN"}},
		{"country", map[string]string{"ANSP_COUNTRY": "GE"}, []string{"ANSP_COUNTRY"}},
		{"instance", map[string]string{"ANSP_INSTANCE": "a b"}, []string{"ANSP_INSTANCE"}},
		{"system id", map[string]string{"ANSP_SYSTEM_ID": "a/b"}, []string{"ANSP_SYSTEM_ID"}},
		{"client id", map[string]string{"ANSP_CLIENT_ID": "a b"}, []string{"ANSP_CLIENT_ID"}},
		{"trusted proxy", map[string]string{"ANSP_TRUSTED_PROXIES": "caddy"}, []string{"ANSP_TRUSTED_PROXIES"}},
		{"origin with a path", map[string]string{"ANSP_WS_ALLOWED_ORIGINS": "https://ansp.example/console"}, []string{"ANSP_WS_ALLOWED_ORIGINS"}},
		{"origin without scheme", map[string]string{"ANSP_WS_ALLOWED_ORIGINS": "ansp.example"}, []string{"ANSP_WS_ALLOWED_ORIGINS"}},
		{"bootstrap half", map[string]string{"ANSP_BOOTSTRAP_ADMIN_USERNAME": "root"}, []string{"ANSP_BOOTSTRAP_ADMIN_USERNAME"}},
		{"lockout bound", map[string]string{"ANSP_LOGIN_LOCKOUT_AFTER": "0"}, []string{"ANSP_LOGIN_LOCKOUT_AFTER"}},
		{"secret file missing", map[string]string{"ANSP_CLIENT_SECRET_FILE": "/nope"}, []string{"ANSP_CLIENT_SECRET_FILE"}},
		{"pool size not a number", map[string]string{"ANSP_DB_MAX_CONNS": "ten"}, []string{"ANSP_DB_MAX_CONNS"}},
		{"pool size zero", map[string]string{"ANSP_DB_MAX_CONNS": "0"}, []string{"ANSP_DB_MAX_CONNS"}},
		{"statement timeout above the bound", map[string]string{"ANSP_DB_STATEMENT_TIMEOUT_S": "301"}, []string{"ANSP_DB_STATEMENT_TIMEOUT_S"}},
		{"two at once", map[string]string{"ANSP_MTLS_MODE": "x", "ANSP_COUNTRY": "x"}, []string{"ANSP_MTLS_MODE", "ANSP_COUNTRY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFrom(env(tc.env), noFiles)
			if got := fieldNames(err); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tc.want)
			}
			if strings.Contains(err.Error(), "%zz") {
				t.Fatalf("error repeats a URL: %v", err)
			}
		})
	}
}

func TestSecretFileEmpty(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{"ANSP_CLIENT_SECRET_FILE": "/s"}), func(string) ([]byte, error) { return []byte(" \n"), nil })
	if !slices.Equal(fieldNames(err), []string{"ANSP_CLIENT_SECRET_FILE"}) || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v", err)
	}
}

func TestSecretFileFromDisk(t *testing.T) {
	p := t.TempDir() + "/secret"
	if err := os.WriteFile(p, []byte("from-disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANSP_PROCESS", "api")
	t.Setenv("ANSP_CLIENT_SECRET_FILE", p)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientSecret != "from-disk" {
		t.Fatalf("secret %q", c.ClientSecret)
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"nats://nats:4222":                                  "nats://nats:4222",
		"nats://token@nats:4222":                            "nats://***@nats:4222",
		"postgres://u:p@h/db?sslmode=require&sslpassword=x": "postgres://***@h/db?sslmode=require&sslpassword=***",
		"not a url": "***",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// deploy/.env.example lists every variable of the catalogue, in order,
// with its default, and nothing else (CLAUDE.md rule 11: no real value).
func TestEnvExampleMatchesCatalogue(t *testing.T) {
	b, err := os.ReadFile("../../deploy/.env.example")
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]string
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		got = append(got, [2]string{k, v})
	}
	if want := Catalogue(); !slices.Equal(got, want) {
		t.Fatalf("deploy/.env.example\n got  %v\n want %v", got, want)
	}
}
