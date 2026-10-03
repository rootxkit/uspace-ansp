package deliver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Response is what one attempt got back.
type Response struct {
	// Status is 0 when nothing was answered (a network error or a
	// timeout).
	Status int
	// Excerpt is the start of the answer, valid UTF-8, at most the
	// policy's ExcerptBytes plus the truncation note.
	Excerpt string
	// RetryAfter is the answer's Retry-After in seconds, 0 when absent.
	RetryAfter time.Duration
	// Err is the transport error, without a token or a body.
	Err string
}

// Verdict is what an attempt's answer means for the job.
type Verdict int

// The verdicts (02 F2 failure rules).
const (
	// Sent: 2xx.
	Sent Verdict = iota
	// Retry: 5xx, 408, 409, 429, a timeout or a network error: retried
	// with backoff while the window and the count allow. A CISP 409 on a
	// publication is the exception: the worker fails it (deterministic).
	Retry
	// Permanent: any other 4xx (or a 1xx or 3xx: redirects are never
	// followed): failed at once, with the excerpt and an alarm.
	Permanent
)

// Judge classifies r.
func Judge(r Response) Verdict {
	switch {
	case r.Status == 0:
		return Retry
	case r.Status >= 200 && r.Status < 300:
		return Sent
	case r.Status >= 500, r.Status == http.StatusConflict, r.Status == http.StatusTooManyRequests, r.Status == http.StatusRequestTimeout:
		return Retry
	}
	return Permanent
}

// Excerpt is the first limit bytes of b as valid UTF-8, followed by a
// note when b was longer (total says how much was read; capped says the
// read itself stopped at the bound).
func Excerpt(b []byte, limit int, capped bool) string {
	if limit < 1 {
		limit = 1
	}
	cut := len(b) > limit
	if cut {
		b = b[:limit]
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	s := strings.ToValidUTF8(string(b), "�")
	switch {
	case capped:
		return s + "... (truncated: the answer is longer than the read bound)"
	case cut:
		return s + "... (truncated)"
	}
	return s
}

// ParseRetryAfter reads a Retry-After header in delay-seconds (an HTTP
// date is not read); 0 when absent, malformed or negative, at most max.
func ParseRetryAfter(v string, maxWait time.Duration) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 10 {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	// Bounded before it is converted: seconds past the bound would
	// overflow a Duration (found by FuzzParseRetryAfter).
	if n > int64(maxWait/time.Second) {
		return maxWait
	}
	return time.Duration(n) * time.Second
}

// do sends req with c and reads at most maxBytes of the answer.
func do(ctx context.Context, c *http.Client, req *http.Request, maxBytes int64, excerptBytes int, maxWait time.Duration) Response {
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return Response{Err: transportReason(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	capped := int64(len(body)) > maxBytes
	if capped {
		body = body[:maxBytes]
		// Drain nothing more: the connection is closed with the body.
	}
	out := Response{Status: resp.StatusCode, Excerpt: Excerpt(body, excerptBytes, capped),
		RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), maxWait)}
	if rerr != nil && !capped {
		out.Err = "reading the answer: " + transportReason(rerr)
	}
	return out
}

// transportReason names a transport failure without the URL's query or
// anything the peer sent.
func transportReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			err = inner
		}
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.ToValidUTF8(s, "?")
}

// NewHTTPClient is the outbox's client: no redirect is followed (a 3xx
// is an answer, never a new target), every request bounded by timeout,
// and, when cert is given, the client certificate presented (the CISP's
// mTLS, M24).
func NewHTTPClient(timeout time.Duration, cert *tls.Certificate, roots *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	tr.MaxIdleConnsPerHost = 8
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ClientCert is the CISP client certificate loaded from PEM files, with
// the subject the CISP's proxy forwards in X-Client-Cert-Subject (Go's
// pkix.Name string, what Caddy writes), which the CISP binds to this
// system's client id (CISP_ANSP_MTLS_SUBJECT, M24).
type ClientCert struct {
	Cert     tls.Certificate
	Subject  string
	NotAfter time.Time
}

// LoadClientCert reads certFile and keyFile and refuses a pair that does
// not match, a certificate that is not valid at now, and one that is not
// for client authentication.
func LoadClientCert(certFile, keyFile string, now time.Time) (*ClientCert, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ANSP_CISP_CLIENT_CERT_FILE, ANSP_CISP_CLIENT_KEY_FILE: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("ANSP_CISP_CLIENT_CERT_FILE: the first certificate does not parse")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("ANSP_CISP_CLIENT_CERT_FILE: the certificate is valid from %s to %s, not now",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasClientAuth(leaf.ExtKeyUsage) {
		return nil, errors.New("ANSP_CISP_CLIENT_CERT_FILE: the certificate's extended key usage does not allow client authentication")
	}
	pair.Leaf = leaf
	return &ClientCert{Cert: pair, Subject: leaf.Subject.String(), NotAfter: leaf.NotAfter}, nil
}

func hasClientAuth(us []x509.ExtKeyUsage) bool {
	for _, u := range us {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// newRequest builds a request with a body that can be read again.
func newRequest(method, url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body)) //nolint:noctx // the context is attached in do
	if err != nil {
		return nil, err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return req, nil
}
