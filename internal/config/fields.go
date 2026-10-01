package config

import (
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// field is one env-tagged field of Config.
type field struct {
	v    reflect.Value
	sf   reflect.StructField
	name string
}

func (f field) tag(k string) string { return f.sf.Tag.Get(k) }

// each calls fn for every env-tagged field of *Config in declaration
// order.
func each(c *Config, fn func(field)) {
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		name, ok := sf.Tag.Lookup("env")
		if !ok {
			continue
		}
		fn(field{v: v.Field(i), sf: sf, name: name})
	}
}

// catalogue is every variable name, in declaration order.
func catalogue() []string {
	var names []string
	each(&Config{}, func(f field) { names = append(names, f.name) })
	return names
}

// Catalogue is every ANSP_* variable with its default, in declaration
// order; deploy/.env.example lists exactly these (a test keeps the two
// in step).
func Catalogue() [][2]string {
	var out [][2]string
	each(&Config{}, func(f field) { out = append(out, [2]string{f.name, f.tag("default")}) })
	return out
}

func (f field) load(vals map[string]string) error {
	raw := strings.TrimSpace(vals[f.name])
	if raw == "" {
		raw = f.tag("default")
		if raw == "" {
			return nil
		}
	}
	if enum := f.tag("enum"); enum != "" && !slices.Contains(strings.Split(enum, "|"), raw) {
		return core.Fieldf(f.name, "%q is not one of %s", raw, strings.ReplaceAll(enum, "|", ", "))
	}
	switch p := f.v.Addr().Interface().(type) {
	case *string:
		if f.tag("kind") == "url" {
			if err := checkURL(raw); err != nil {
				// The value is not repeated: a URL may carry a password.
				return core.Fieldf(f.name, "%s", err.Error())
			}
		}
		*p = raw
	case *[]string:
		*p = splitList(raw)
	case *[]Issuer:
		iss, err := ParseIssuers(splitList(raw))
		if err != nil {
			return core.Fieldf(f.name, "%s", err.Error())
		}
		*p = iss
	default:
		return core.Fieldf(f.name, "unsupported field type %s", f.v.Type())
	}
	return nil
}

func splitList(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Redacted is every variable with its effective value, for the start-up
// log line: the user information of a URL (a password or a token) is
// "***", file paths are shown (the secret is the file's content, which
// is never in Config's tagged fields), unset values are "".
func (c Config) Redacted() map[string]string {
	out := map[string]string{}
	each(&c, func(f field) {
		var val string
		switch v := f.v.Interface().(type) {
		case string:
			val = v
		case []string:
			val = strings.Join(v, ",")
		case []Issuer:
			parts := make([]string, 0, len(v))
			for _, i := range v {
				parts = append(parts, i.Issuer+"="+i.JWKSURL)
			}
			val = strings.Join(parts, ",")
		}
		if f.tag("secret") == "userinfo" && val != "" {
			val = redactURL(val)
		}
		out[f.name] = val
	})
	return out
}

// RedactedNames is the sorted list of the names in Redacted.
func (c Config) RedactedNames() []string {
	names := catalogue()
	sort.Strings(names)
	return names
}

// credentialParams are the query parameters redactURL hides.
var credentialParams = []string{"password", "pass", "sslpassword", "token", "secret"}

// redactURL replaces the user information and the credential query
// parameters with "***". A value that does not parse is redacted whole.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "***"
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if slices.ContainsFunc(credentialParams, func(p string) bool { return strings.EqualFold(p, k) }) {
				q.Set(k, "***")
			}
		}
		u.RawQuery = q.Encode()
	}
	return strings.ReplaceAll(u.String(), "%2A%2A%2A", "***")
}
