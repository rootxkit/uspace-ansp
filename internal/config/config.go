package config

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// The three processes (CLAUDE.md conventions; tests/layout_test.go
// keeps cmd/ in step).
const (
	ProcessAPI           = "api"
	ProcessMannedAdapter = "manned-adapter"
	ProcessMannedFeed    = "manned-feed"
)

// Processes lists the three, in docs/PLAN.md section 3 order.
var Processes = []string{ProcessAPI, ProcessMannedAdapter, ProcessMannedFeed}

// The two values of ANSP_MTLS_MODE (M25).
const (
	MTLSRequired = "required"
	MTLSOff      = "off"
)

// Issuer is one issuer allowed to sign tokens, with the URL of its JWKS.
type Issuer struct {
	Issuer  string
	JWKSURL string
}

// Config is the configuration of one process. Fields carry their
// variable in the env tag and, when the variable may be unset, its
// default; the catalogue is the set of env tags.
type Config struct {
	// Process is set by the entrypoint: api, manned-adapter or manned-feed.
	Process string `env:"ANSP_PROCESS"`
	// Instance tells processes of the same kind apart in logs and metrics.
	Instance string `env:"ANSP_INSTANCE" default:"local"`
	// SystemID is a label for logs and the envelope producer; it is never
	// a JWT audience.
	SystemID string `env:"ANSP_SYSTEM_ID" default:"ansp"`
	// Audiences are the hosts this system accepts as aud: its public host
	// plus a lab alias (M18).
	Audiences []string `env:"ANSP_AUDIENCES"`
	HTTPAddr  string   `env:"ANSP_HTTP_ADDR" default:":8080"`

	NATSURL string `env:"ANSP_NATS_URL" kind:"url" secret:"userinfo"`
	// NATSCreds is the path of this process's NATS credentials file.
	NATSCreds string `env:"ANSP_NATS_CREDS"`

	RelationalDSN string `env:"ANSP_RELATIONAL_DSN" kind:"url" secret:"userinfo"`
	TimeseriesDSN string `env:"ANSP_TIMESERIES_DSN" kind:"url" secret:"userinfo"`
	// DBMaxConns bounds each process's pool per database.
	DBMaxConns int `env:"ANSP_DB_MAX_CONNS" default:"10" min:"1" max:"100"`
	// DBAcquireTimeoutS bounds the wait for a pooled connection: past it
	// the call is refused, never left hanging (E-10).
	DBAcquireTimeoutS int `env:"ANSP_DB_ACQUIRE_TIMEOUT_S" default:"5" min:"1" max:"60"`
	// DBStatementTimeoutS bounds every statement and every lock wait.
	DBStatementTimeoutS int `env:"ANSP_DB_STATEMENT_TIMEOUT_S" default:"5" min:"1" max:"300"`
	// DBTxTimeoutS bounds a transaction that has no deadline of its own
	// and an idle transaction on the server.
	DBTxTimeoutS int `env:"ANSP_DB_TX_TIMEOUT_S" default:"15" min:"1" max:"600"`

	// TokenIssuers are the issuers of the tokens this system accepts
	// (the authority and, in the lab, the lab issuer), as iss=jwks_url.
	TokenIssuers []Issuer `env:"ANSP_TOKEN_ISSUERS"`
	// TokenURL is the token endpoint this system's client uses.
	TokenURL string `env:"ANSP_TOKEN_URL" kind:"url"`
	ClientID string `env:"ANSP_CLIENT_ID" default:"ansp-01"`
	// ClientSecretFile is the path of the client secret; ClientSecret is
	// its content, read at load and never logged.
	ClientSecretFile string `env:"ANSP_CLIENT_SECRET_FILE"`
	ClientSecret     string

	CISPURL string `env:"ANSP_CISP_URL" kind:"url"`
	// CISNotifyIssuers are the issuers accepted on /v1/cis/notifications
	// (the CISP), as iss=jwks_url.
	CISNotifyIssuers []Issuer `env:"ANSP_CIS_NOTIFY_ISSUERS"`
	// DSSURL is the DSS base URL; its host is the DSS audience.
	DSSURL       string `env:"ANSP_DSS_URL" kind:"url"`
	AuthorityURL string `env:"ANSP_AUTHORITY_URL" kind:"url"`
	// PublicBaseURL is the uss_base_url written to the DSS, the
	// callback_url base and the host of this system's own aud.
	PublicBaseURL string `env:"ANSP_PUBLIC_BASE_URL" kind:"url"`

	MTLSMode string `env:"ANSP_MTLS_MODE" default:"required" enum:"required|off"`
	// MTLSBindingsFile maps a client's sub to the subject of its client
	// certificate (M25); an unmapped sub is refused on the mTLS routes.
	MTLSBindingsFile string `env:"ANSP_MTLS_BINDINGS_FILE"`
	// TrustedProxies are the reverse proxies (CIDRs or addresses) whose
	// X-Forwarded-For is believed; nobody else's is.
	TrustedProxies []string `env:"ANSP_TRUSTED_PROXIES"`
	// WSAllowedOrigins are the origins (scheme://host[:port]) a browser
	// WebSocket upgrade with the session cookie may come from (M22).
	WSAllowedOrigins []string `env:"ANSP_WS_ALLOWED_ORIGINS"`

	// SessionKeyFile is the PEM RSA key that signs console sessions;
	// SecretsKeyFile the 32-byte key that seals TOTP secrets at rest.
	SessionKeyFile string `env:"ANSP_SESSION_KEY_FILE"`
	SecretsKeyFile string `env:"ANSP_SECRETS_KEY_FILE"`
	// Sign-in limits (S-15): per address and per username per minute in
	// each process, and the lockout of a username in the database after
	// LoginLockoutAfter failures for LoginLockoutS.
	LoginIPPerMin     int `env:"ANSP_LOGIN_IP_PER_MIN" default:"10" min:"1" max:"1000"`
	LoginUserPerMin   int `env:"ANSP_LOGIN_USER_PER_MIN" default:"5" min:"1" max:"1000"`
	LoginLockoutAfter int `env:"ANSP_LOGIN_LOCKOUT_AFTER" default:"10" min:"1" max:"100"`
	LoginLockoutS     int `env:"ANSP_LOGIN_LOCKOUT_S" default:"900" min:"60" max:"86400"`
	// The first admin, created at start when the users table is empty:
	// the username and the path of a file holding the password.
	BootstrapAdminUsername     string `env:"ANSP_BOOTSTRAP_ADMIN_USERNAME"`
	BootstrapAdminPasswordFile string `env:"ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE"`

	LogLevel     string `env:"ANSP_LOG_LEVEL" default:"info" enum:"debug|info|warn|error"`
	OTLPEndpoint string `env:"ANSP_OTLP_ENDPOINT" kind:"url"`
	Country      string `env:"ANSP_COUNTRY" default:"GEO"`
}

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	return LoadFrom(os.Environ(), os.ReadFile)
}

// LoadFrom reads the configuration from environ (os.Environ form),
// reading secret files with readFile. The error, when not nil, joins one
// *core.FieldError per problem.
func LoadFrom(environ []string, readFile func(string) ([]byte, error)) (Config, error) {
	vals := map[string]string{}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(name, Prefix) {
			vals[name] = value
		}
	}
	var c Config
	var errs []error
	names := catalogue()
	unknown := make([]string, 0)
	for name := range vals {
		if !slices.Contains(names, name) {
			unknown = append(unknown, name)
		}
	}
	slices.Sort(unknown)
	for _, name := range unknown {
		errs = append(errs, core.Fieldf(name, "unknown variable; check the spelling against deploy/.env.example"))
	}
	each(&c, func(f field) {
		if err := f.load(vals); err != nil {
			errs = append(errs, err)
		}
	})
	if c.ClientSecretFile != "" {
		b, err := readFile(c.ClientSecretFile)
		switch {
		case err != nil:
			errs = append(errs, core.Fieldf("ANSP_CLIENT_SECRET_FILE", "cannot be read: %s", pathErrorReason(err)))
		case strings.TrimSpace(string(b)) == "":
			errs = append(errs, core.Fieldf("ANSP_CLIENT_SECRET_FILE", "the file is empty"))
		default:
			c.ClientSecret = strings.TrimSpace(string(b))
		}
	}
	errs = append(errs, c.validate()...)
	return c, errors.Join(errs...)
}

// Prefix is the namespace of every variable of this system.
const Prefix = "ANSP_"

// pathErrorReason is the reason of a file error without the path or
// operation, which the variable name already says.
func pathErrorReason(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

var (
	hostPattern    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

func (c *Config) validate() []error {
	var errs []error
	if c.Process == "" {
		errs = append(errs, core.Fieldf("ANSP_PROCESS", "required; set by the entrypoint to one of %s", strings.Join(Processes, ", ")))
	} else if !slices.Contains(Processes, c.Process) {
		errs = append(errs, core.Fieldf("ANSP_PROCESS", "%q is not one of %s", c.Process, strings.Join(Processes, ", ")))
	}
	if !idPattern.MatchString(c.Instance) {
		errs = append(errs, core.Fieldf("ANSP_INSTANCE", "must be 1-64 of A-Z a-z 0-9 . _ -"))
	}
	if !idPattern.MatchString(c.SystemID) {
		errs = append(errs, core.Fieldf("ANSP_SYSTEM_ID", "must be 1-64 of A-Z a-z 0-9 . _ -"))
	}
	if !idPattern.MatchString(c.ClientID) {
		errs = append(errs, core.Fieldf("ANSP_CLIENT_ID", "must be 1-64 of A-Z a-z 0-9 . _ -"))
	}
	for _, h := range c.Audiences {
		if !hostPattern.MatchString(h) {
			errs = append(errs, core.Fieldf("ANSP_AUDIENCES", "%q is not a host (no scheme, path or user)", h))
		}
		if h == c.SystemID {
			errs = append(errs, core.Fieldf("ANSP_AUDIENCES", "%q is ANSP_SYSTEM_ID, which is never an audience", h))
		}
	}
	if c.PublicBaseURL != "" && len(c.Audiences) > 0 {
		if u, err := url.Parse(c.PublicBaseURL); err == nil && !slices.Contains(c.Audiences, u.Host) {
			errs = append(errs, core.Fieldf("ANSP_AUDIENCES", "does not contain %q, the host of ANSP_PUBLIC_BASE_URL", u.Host))
		}
	}
	if c.RelationalDSN != "" && c.RelationalDSN == c.TimeseriesDSN {
		// CLAUDE.md rule 6: two trees, two databases, never one.
		errs = append(errs, core.Fieldf("ANSP_TIMESERIES_DSN", "must name a different database from ANSP_RELATIONAL_DSN"))
	}
	for _, p := range c.TrustedProxies {
		if !validProxy(p) {
			errs = append(errs, core.Fieldf("ANSP_TRUSTED_PROXIES", "%q is neither a CIDR nor an address", p))
		}
	}
	for _, o := range c.WSAllowedOrigins {
		if !validOrigin(o) {
			errs = append(errs, core.Fieldf("ANSP_WS_ALLOWED_ORIGINS", "%q is not an origin (scheme://host[:port], no path)", o))
		}
	}
	if (c.BootstrapAdminUsername == "") != (c.BootstrapAdminPasswordFile == "") {
		errs = append(errs, core.Fieldf("ANSP_BOOTSTRAP_ADMIN_USERNAME", "set together with ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE, or neither"))
	}
	if !countryPattern.MatchString(c.Country) {
		errs = append(errs, core.Fieldf("ANSP_COUNTRY", "%q is not an ISO 3166-1 alpha-3 code", c.Country))
	}
	return errs
}

// ParseIssuers splits iss=jwks_url entries at the first "=" and checks
// that both are absolute URLs.
func ParseIssuers(entries []string) ([]Issuer, error) {
	out := make([]Issuer, 0, len(entries))
	for _, e := range entries {
		iss, jwks, ok := strings.Cut(e, "=")
		iss, jwks = strings.TrimSpace(iss), strings.TrimSpace(jwks)
		if !ok || iss == "" || jwks == "" {
			return nil, errors.New("each entry must be iss=jwks_url")
		}
		if err := checkURL(iss); err != nil {
			return nil, errors.New("the issuer " + iss + " " + err.Error())
		}
		if err := checkURL(jwks); err != nil {
			return nil, errors.New("the JWKS URL of " + iss + " " + err.Error())
		}
		if slices.ContainsFunc(out, func(i Issuer) bool { return i.Issuer == iss }) {
			return nil, errors.New("the issuer " + iss + " is listed twice")
		}
		out = append(out, Issuer{Issuer: iss, JWKSURL: jwks})
	}
	return out, nil
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return errors.New("must be an absolute URL with a scheme and a host")
	}
	return nil
}

// validProxy reports whether p is a CIDR or a single address.
func validProxy(p string) bool {
	if _, err := netip.ParsePrefix(p); err == nil {
		return true
	}
	_, err := netip.ParseAddr(p)
	return err == nil
}

// validOrigin reports whether o is an origin as browsers send it:
// http or https, a host, an optional port, nothing else.
func validOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && o == u.Scheme+"://"+u.Host
}
