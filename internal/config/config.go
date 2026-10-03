package config

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

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
	// CISPublisherKeys are the JWKS of the CIS publishers as
	// publisher=jwks_url (authority, ansp): a dataset version is used
	// only when its X-Publisher-Signature verifies with its publisher's
	// key (the authority for uspace_airspace and ussp_list, this system
	// for restrictions); otherwise it is held (WP-7).
	CISPublisherKeys []string `env:"ANSP_CIS_PUBLISHER_KEYS"`
	// CISPublisherSigMaxAgeS is how old the iat of a publisher signature
	// may be when this system first reads its version: the CISP forwards
	// the signature made at publication, so it is as old as the version.
	CISPublisherSigMaxAgeS int `env:"ANSP_CIS_PUBLISHER_SIG_MAX_AGE_S" default:"31622400" min:"300" max:"315360000"`
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
	// X-Forwarded-For and X-Client-Cert-Subject are believed; nobody
	// else's is. Empty trusts no proxy.
	TrustedProxies []string `env:"ANSP_TRUSTED_PROXIES"`
	// WSAllowedOrigins are the origins (scheme://host[:port]) a browser
	// WebSocket upgrade with the session cookie may come from (M22).
	WSAllowedOrigins []string `env:"ANSP_WS_ALLOWED_ORIGINS"`

	// DeliveryKeyFile is the PEM RSA key that signs what this system
	// delivers (WP-8, M26, M27): the detached JWS of every CISP
	// publication and the compact JWS of every degraded direct
	// delivery; its public part is served in /.well-known/jwks.json.
	DeliveryKeyFile string `env:"ANSP_DELIVERY_KEY_FILE"`
	// CISPClientCertFile and CISPClientKeyFile are the PEM client
	// certificate and key presented to the CISP on the publication and
	// the heartbeat (02 F2, M24); both or neither.
	CISPClientCertFile string `env:"ANSP_CISP_CLIENT_CERT_FILE"`
	CISPClientKeyFile  string `env:"ANSP_CISP_CLIENT_KEY_FILE"`

	// SessionKeyFile is the PEM RSA key that signs console sessions;
	// SecretsKeyFile the 32-byte key that seals TOTP secrets and the
	// occurrence reporter references (WP-10) at rest.
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

	// manned-adapter (WP-4): the kind of feed, the instance id (the
	// source_instance of its tracks and the <adapter> of its subjects),
	// the source class of its tracks and the kind's connection settings.
	AdapterKind        string `env:"ANSP_ADAPTER_KIND" enum:"replay|dump1090_sbs|dump1090_json|asterix_cat021"`
	AdapterID          string `env:"ANSP_ADAPTER_ID"`
	AdapterSourceClass string `env:"ANSP_ADAPTER_SOURCE_CLASS" enum:"ads_b|mode_s|ssr|atm_feed|ads_l"`
	// AdapterSBSAddr is dump1090's BaseStation output, host:port.
	AdapterSBSAddr string `env:"ANSP_ADAPTER_SBS_ADDR"`
	// AdapterSBSTimezone is the zone of the SBS time columns, which
	// dump1090 writes in the receiver's local time (IANA name).
	AdapterSBSTimezone string `env:"ANSP_ADAPTER_SBS_TIMEZONE" default:"UTC"`
	// AdapterJSONURL is where dump1090 serves aircraft.json.
	AdapterJSONURL string `env:"ANSP_ADAPTER_JSON_URL" kind:"url"`
	// The replay adapter: the synthetic NDJSON file, whether replay may
	// run at all (never by default, 06 T11), its speed and loop.
	AdapterReplayFile    string  `env:"ANSP_ADAPTER_REPLAY_FILE"`
	AdapterReplayAllowed string  `env:"ANSP_ADAPTER_REPLAY_ALLOWED" default:"false" enum:"true|false"`
	AdapterReplaySpeed   float64 `env:"ANSP_ADAPTER_REPLAY_SPEED" default:"1" min:"0.01" max:"1000"`
	AdapterReplayLoop    string  `env:"ANSP_ADAPTER_REPLAY_LOOP" default:"false" enum:"true|false"`

	LogLevel     string `env:"ANSP_LOG_LEVEL" default:"info" enum:"debug|info|warn|error"`
	OTLPEndpoint string `env:"ANSP_OTLP_ENDPOINT" kind:"url"`
	Country      string `env:"ANSP_COUNTRY" default:"GEO"`

	// api (WP-5): the GeographicLib geoid grid that makes a restriction's
	// AMSL limits W84 for its F3548 constraint (empty: AMSL restrictions
	// are refused with geoid_unavailable), and the zone authority every
	// restriction feature names (branding is configuration).
	GeoidFile        string `env:"ANSP_GEOID_FILE"`
	AuthorityName    string `env:"ANSP_AUTHORITY_NAME" default:"ANSP"`
	AuthorityService string `env:"ANSP_AUTHORITY_SERVICE"`
	AuthorityEmail   string `env:"ANSP_AUTHORITY_EMAIL"`
	AuthorityPhone   string `env:"ANSP_AUTHORITY_PHONE"`
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
	// adapterIDPattern is track/manned/v1's source_instance pattern: the
	// id is also one NATS subject token.
	adapterIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
)

// validateAdapter checks the manned-adapter settings: a kind, an id, a
// source class, and the setting the kind reads.
func (c *Config) validateAdapter() []error {
	var errs []error
	if c.AdapterKind == "" {
		errs = append(errs, core.Fieldf("ANSP_ADAPTER_KIND", "required for %s", ProcessMannedAdapter))
	}
	if len(c.AdapterID) > 64 || !adapterIDPattern.MatchString(c.AdapterID) {
		errs = append(errs, core.Fieldf("ANSP_ADAPTER_ID", "required: lower-case words of a-z 0-9 joined by -, at most 64 characters"))
	}
	if c.AdapterSourceClass == "" {
		errs = append(errs, core.Fieldf("ANSP_ADAPTER_SOURCE_CLASS", "required for %s", ProcessMannedAdapter))
	}
	switch c.AdapterKind {
	case "dump1090_sbs":
		if _, _, err := net.SplitHostPort(c.AdapterSBSAddr); err != nil {
			errs = append(errs, core.Fieldf("ANSP_ADAPTER_SBS_ADDR", "required for dump1090_sbs: host:port"))
		}
		if _, err := time.LoadLocation(c.AdapterSBSTimezone); err != nil {
			errs = append(errs, core.Fieldf("ANSP_ADAPTER_SBS_TIMEZONE", "%q is not a time zone", c.AdapterSBSTimezone))
		}
	case "dump1090_json":
		if u, err := url.Parse(c.AdapterJSONURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, core.Fieldf("ANSP_ADAPTER_JSON_URL", "required for dump1090_json: an http(s) URL"))
		}
	case "replay":
		if c.AdapterReplayFile == "" {
			errs = append(errs, core.Fieldf("ANSP_ADAPTER_REPLAY_FILE", "required for replay"))
		}
	}
	return errs
}

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
	if (c.CISPClientCertFile == "") != (c.CISPClientKeyFile == "") {
		errs = append(errs, core.Fieldf("ANSP_CISP_CLIENT_CERT_FILE", "set together with ANSP_CISP_CLIENT_KEY_FILE, or neither"))
	}
	if (c.BootstrapAdminUsername == "") != (c.BootstrapAdminPasswordFile == "") {
		errs = append(errs, core.Fieldf("ANSP_BOOTSTRAP_ADMIN_USERNAME", "set together with ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE, or neither"))
	}
	if c.Process == ProcessMannedAdapter {
		errs = append(errs, c.validateAdapter()...)
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
