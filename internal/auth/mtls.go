package auth

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// HeaderClientCertSubject is the header Caddy sets from a verified
// client certificate on the mTLS route groups and strips everywhere
// else (M25; the Caddy snippet is WP-13's). It is believed only from a
// peer in ANSP_TRUSTED_PROXIES: anyone else could write it.
const HeaderClientCertSubject = "X-Client-Cert-Subject"

// Bounds of the bindings file.
const (
	MaxBindingsFileBytes = 1 << 20
	MaxBindings          = 1000
	MaxSubjectBytes      = 1024
)

// Counters of the mTLS binding.
const (
	CounterMTLSAbsent        = "mtls_subject_absent"
	CounterMTLSUntrustedPeer = "mtls_subject_untrusted_peer"
	CounterMTLSUnbound       = "mtls_sub_unbound"
	CounterMTLSMismatch      = "mtls_subject_mismatch"
	CounterMTLSAccepted      = "mtls_subject_accepted"
	CounterMTLSOffSkipped    = "mtls_off_unchecked"
)

// Binding is one entry of ANSP_MTLS_BINDINGS_FILE.
type Binding struct {
	Sub     string `json:"sub"`
	Subject string `json:"subject"`
}

// LoadMTLSBindings reads ANSP_MTLS_BINDINGS_FILE: a JSON array of
// {"sub", "subject"}, each sub once (B-14: a duplicate is refused, not
// resolved), each subject non-empty, at most MaxBindings entries.
func LoadMTLSBindings(path string) (map[string]string, error) {
	raw, err := readBounded("ANSP_MTLS_BINDINGS_FILE", path, MaxBindingsFileBytes)
	if err != nil {
		return nil, err
	}
	return ParseMTLSBindings(raw)
}

// ParseMTLSBindings is LoadMTLSBindings on the file's content.
func ParseMTLSBindings(raw []byte) (map[string]string, error) {
	var list []Binding
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "not a JSON array of {sub, subject}")
	}
	if len(list) > MaxBindings {
		return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "more than %d bindings", MaxBindings)
	}
	out := make(map[string]string, len(list))
	for i, b := range list {
		sub, subject := strings.TrimSpace(b.Sub), strings.TrimSpace(b.Subject)
		switch {
		case sub == "" || subject == "":
			return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "entry %d: sub and subject are required", i)
		case len(subject) > MaxSubjectBytes || !utf8.ValidString(subject):
			return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "entry %d: the subject is not valid UTF-8 of at most %d bytes", i, MaxSubjectBytes)
		}
		if _, dup := out[sub]; dup {
			return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "sub %q is bound twice", sub)
		}
		out[sub] = subject
	}
	return out, nil
}

// MTLS binds the certificate Caddy verified to the token's sub on the
// mTLS route groups (/v1/manned-traffic/*, /v1/coordination/*). With
// ANSP_MTLS_MODE=required the header must be present, once, and equal
// the subject configured for sub; an unmapped sub is refused (no trust
// on first use). The header is read only when the request's peer
// (r.RemoteAddr) is one of ANSP_TRUSTED_PROXIES; from any other peer
// it is ignored, so the request has no client certificate and is
// refused as absent (counted as mtls_subject_untrusted_peer). With no
// trusted proxy configured no header is ever believed. With off
// nothing is checked, counted as mtls_off_unchecked; obs.Server logs
// the mode at error level every status period so a staging setting
// cannot reach production unnoticed.
type MTLS struct {
	mode     string
	bindings map[string]string
	proxies  []netip.Prefix
	counters core.Counters
}

// NewMTLS builds the binding for mode (config.MTLSRequired or
// config.MTLSOff). required needs bindings. proxies are the peers whose
// X-Client-Cert-Subject is believed (ParseTrustedProxies).
func NewMTLS(mode string, bindings map[string]string, proxies []netip.Prefix) (*MTLS, error) {
	switch mode {
	case config.MTLSOff:
	case config.MTLSRequired:
		if len(bindings) == 0 {
			return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE", "required (and not empty) when ANSP_MTLS_MODE=required")
		}
	default:
		return nil, core.Fieldf("ANSP_MTLS_MODE", "%q is not required or off", mode)
	}
	return &MTLS{mode: mode, bindings: bindings, proxies: proxies}, nil
}

// Mode is required or off.
func (m *MTLS) Mode() string { return m.mode }

// Counters are the binding's counters.
func (m *MTLS) Counters() *core.Counters { return &m.counters }

// Check binds r's certificate subject to sub and returns the subject
// ("" when off). A refusal is an *Error (403) that names neither the
// expected subject nor the received one.
func (m *MTLS) Check(r *http.Request, sub string) (string, error) {
	if m.mode == config.MTLSOff {
		m.counters.Inc(CounterMTLSOffSkipped)
		return "", nil
	}
	var vals []string
	if m.fromTrustedProxy(r) {
		vals = r.Header.Values(HeaderClientCertSubject)
	} else if len(r.Header.Values(HeaderClientCertSubject)) > 0 {
		m.counters.Inc(CounterMTLSUntrustedPeer)
	}
	if len(vals) != 1 || strings.TrimSpace(vals[0]) == "" {
		m.counters.Inc(CounterMTLSAbsent)
		return "", refusal(http.StatusForbidden, SlugMTLSRequired, "this route requires a client certificate (mTLS)",
			FieldReason{Field: HeaderClientCertSubject, Reason: "absent"})
	}
	want, ok := m.bindings[sub]
	if !ok {
		m.counters.Inc(CounterMTLSUnbound)
		return "", refusal(http.StatusForbidden, SlugMTLSMismatch, "no client certificate is bound to this client",
			FieldReason{Field: "sub", Reason: "no binding"})
	}
	got := strings.TrimSpace(vals[0])
	if got != want {
		m.counters.Inc(CounterMTLSMismatch)
		return "", refusal(http.StatusForbidden, SlugMTLSMismatch, "the client certificate is not the one bound to this client",
			FieldReason{Field: HeaderClientCertSubject, Reason: "does not match the binding of sub"})
	}
	m.counters.Inc(CounterMTLSAccepted)
	return got, nil
}

// fromTrustedProxy is whether r's peer is in ANSP_TRUSTED_PROXIES. The
// peer is r.RemoteAddr, never X-Forwarded-For: the header names the
// certificate the connecting proxy verified, so only that proxy counts.
func (m *MTLS) fromTrustedProxy(r *http.Request) bool {
	if len(m.proxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return trusted(a, m.proxies)
}
