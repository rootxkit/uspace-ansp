package dss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/auth"
)

// Tokens fetches client-credentials tokens (internal/auth.TokenSource):
// one per (aud, scopes), aud the host of the target's base URL (M18).
type Tokens interface {
	TokenFor(ctx context.Context, audience string, scopes []string) (string, error)
}

// Call is what one request got back, for the attempt log.
type Call struct {
	Method string
	Path   string
	// Status is 0 when nothing was answered.
	Status int
	// Excerpt is the start of the answer, valid UTF-8.
	Excerpt    string
	RetryAfter time.Duration
	// Err is the transport or local failure, without a token or a body.
	Err string
}

// The kinds of failure of a DSS call (errors.Is on the *Error).
var (
	// ErrConflict: 409, a stale ovn or a reference that exists already.
	ErrConflict = errors.New("the DSS answered 409")
	// ErrNotFound: 404, no such reference.
	ErrNotFound = errors.New("the DSS answered 404")
	// ErrUnavailable: no answer, a timeout, 5xx, 408 or 429 (retried).
	ErrUnavailable = errors.New("the DSS is unreachable")
	// ErrRefused: any other answer that is not the operation's success
	// (a 4xx, a redirect: never followed).
	ErrRefused = errors.New("the DSS refused the call")
	// ErrMalformed: a success whose body this system cannot use, or a
	// call it could not build (no token, a bad base URL).
	ErrMalformed = errors.New("the DSS answer cannot be used")
)

// Error is a failed call: Kind is one of the Err* values, Call what was
// answered, Reason why.
type Error struct {
	Kind   error
	Call   Call
	Reason string
	// Cause is what made an answer unusable (errors.Is reaches it, e.g.
	// ErrTooManySubscribers).
	Cause error
}

func (e *Error) Error() string {
	if e.Call.Status != 0 {
		return fmt.Sprintf("%s %s: HTTP %d: %s", e.Call.Method, e.Call.Path, e.Call.Status, e.Reason)
	}
	return fmt.Sprintf("%s %s: %s", e.Call.Method, e.Call.Path, e.Reason)
}

func (e *Error) Unwrap() []error {
	if e.Cause != nil {
		return []error{e.Kind, e.Cause}
	}
	return []error{e.Kind}
}

// CallOf is the Call of err, or an empty one.
func CallOf(err error) Call {
	var e *Error
	if errors.As(err, &e) {
		return e.Call
	}
	return Call{}
}

// Client calls the DSS's constraint-reference operations with a token
// of utm.constraint_management whose aud is the DSS's host (M18). Every
// answer is read up to MaxResponseBytes and decoded with DecodeChange or
// DecodeReference. It remembers whether the DSS last answered, for the
// readiness line (Status). Safe for concurrent use.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Tokens  Tokens
	// MaxResponseBytes bounds an answer read (f3548.MaxMessageBytes by
	// default); MaxSubscribers bounds the subscriptions of one answer.
	MaxResponseBytes int
	MaxSubscribers   int
	// ExcerptBytes bounds the excerpt kept of an answer.
	ExcerptBytes int
	// MaxRetryAfter bounds a Retry-After honoured.
	MaxRetryAfter time.Duration
	// Now is the clock of the readiness line; nil is time.Now.
	Now func() time.Time

	mu     sync.Mutex
	known  bool
	up     bool
	since  time.Time
	reason string
	last   time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) maxBytes() int {
	if c.MaxResponseBytes > 0 {
		return c.MaxResponseBytes
	}
	return f3548.MaxMessageBytes
}

func (c *Client) excerptBytes() int {
	if c.ExcerptBytes > 0 {
		return c.ExcerptBytes
	}
	return 1024
}

// PutBody is the PutConstraintReferenceParameters of a constraint: its
// extents and this system's uss_base_url (no trailing '/', as the
// standard says).
func PutBody(extents []f3548.Volume4D, ussBaseURL string) ([]byte, error) {
	if len(extents) == 0 {
		return nil, errors.New("a constraint reference needs at least one extent")
	}
	return json.Marshal(f3548.PutConstraintReferenceParameters{Extents: extents, UssBaseUrl: strings.TrimRight(ussBaseURL, "/")})
}

// PutReference creates (ovn nil) or updates (with the current ovn)
// reference id with body (PutBody's bytes).
func (c *Client) PutReference(ctx context.Context, id string, body []byte, ovn *string) (f3548.ChangeConstraintReferenceResponse, Call, error) {
	op := Op(OpCreateReference)
	if ovn != nil {
		op = Op(OpUpdateReference)
	}
	call, data, err := c.do(ctx, op, ReferencePath(id, ovn), body)
	if err != nil {
		return f3548.ChangeConstraintReferenceResponse{}, call, err
	}
	resp, derr := DecodeChange(data, id, true, c.maxBytes(), c.maxSubscribers())
	if derr != nil {
		return resp, call, &Error{Kind: ErrMalformed, Call: call, Reason: "the answer is not a usable ChangeConstraintReferenceResponse: " + derr.Error(), Cause: derr}
	}
	return resp, call, nil
}

// DeleteReference deletes reference id at ovn.
func (c *Client) DeleteReference(ctx context.Context, id, ovn string) (f3548.ChangeConstraintReferenceResponse, Call, error) {
	call, data, err := c.do(ctx, Op(OpDeleteReference), ReferencePath(id, &ovn), nil)
	if err != nil {
		return f3548.ChangeConstraintReferenceResponse{}, call, err
	}
	resp, derr := DecodeChange(data, id, false, c.maxBytes(), c.maxSubscribers())
	if derr != nil {
		return resp, call, &Error{Kind: ErrMalformed, Call: call, Reason: "the answer is not a usable ChangeConstraintReferenceResponse: " + derr.Error(), Cause: derr}
	}
	return resp, call, nil
}

// GetReference reads reference id (its ovn is there: this system is its
// manager).
func (c *Client) GetReference(ctx context.Context, id string) (f3548.ConstraintReference, Call, error) {
	call, data, err := c.do(ctx, Op(OpGetReference), ReferencePath(id, nil), nil)
	if err != nil {
		return f3548.ConstraintReference{}, call, err
	}
	ref, derr := DecodeReference(data, id, c.maxBytes())
	if derr != nil {
		return ref, call, &Error{Kind: ErrMalformed, Call: call, Reason: "the answer is not a usable GetConstraintReferenceResponse: " + derr.Error(), Cause: derr}
	}
	return ref, call, nil
}

// PingID is the reference a reachability check reads: the nil UUID's
// version 4 form, which this system never mints.
const PingID = "00000000-0000-4000-8000-000000000000"

// Ping reads PingID: a 404 (or any answer of the DSS) says it is
// reachable and takes the token, so the readiness line knows the DSS
// before the first restriction.
func (c *Client) Ping(ctx context.Context) error {
	_, _, err := c.GetReference(ctx, PingID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func (c *Client) maxSubscribers() int {
	if c.MaxSubscribers > 0 {
		return c.MaxSubscribers
	}
	return DefaultMaxSubscribers
}

// DefaultMaxSubscribers bounds the subscriptions of one DSS answer when
// the policy gives none.
const DefaultMaxSubscribers = 10000

// do sends one call of op on path and reads the answer; the error is an
// *Error of the kind the answer is.
func (c *Client) do(ctx context.Context, op Operation, path string, body []byte) (Call, []byte, error) {
	call := Call{Method: op.Method, Path: path}
	fail := func(kind error, reason string) (Call, []byte, error) {
		if call.Err == "" && call.Status == 0 {
			call.Err = reason
		}
		return call, nil, &Error{Kind: kind, Call: call, Reason: reason}
	}
	aud, err := auth.AudienceOf(c.BaseURL)
	if err != nil {
		return fail(ErrMalformed, "ANSP_DSS_URL is not an absolute http(s) URL")
	}
	if c.Tokens == nil {
		// Not the DSS's fault: retried, and the readiness line is not
		// told the DSS is down (the token client's own line says why).
		return fail(ErrUnavailable, "no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE)")
	}
	tok, err := c.Tokens.TokenFor(ctx, aud, []string{op.Scope()})
	if err != nil {
		return fail(ErrUnavailable, "token: "+clip(err.Error(), 300))
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return fail(ErrMalformed, "request: "+clip(err.Error(), 300))
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		reason := TransportReason(err)
		if ctx.Err() == nil {
			c.observe(false, reason)
		}
		return fail(ErrUnavailable, reason)
	}
	defer func() { _ = resp.Body.Close() }()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, int64(c.maxBytes())+1))
	capped := len(data) > c.maxBytes()
	call.Status = resp.StatusCode
	call.Excerpt = Excerpt(data, c.excerptBytes(), capped)
	call.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), c.MaxRetryAfter)
	switch {
	case resp.StatusCode >= 500, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusRequestTimeout:
		reason := "HTTP " + strconv.Itoa(resp.StatusCode)
		c.observe(false, reason)
		return fail(ErrUnavailable, reason)
	}
	// Any other answer is the DSS answering.
	c.observe(true, "")
	switch {
	case resp.StatusCode == http.StatusConflict:
		return fail(ErrConflict, "409: the ovn is not the current one, or the reference exists already")
	case resp.StatusCode == http.StatusNotFound:
		return fail(ErrNotFound, "404: no such constraint reference")
	case resp.StatusCode != op.Success:
		return fail(ErrRefused, fmt.Sprintf("%d, not the %d of %s", resp.StatusCode, op.Success, op.ID))
	case capped:
		return fail(ErrMalformed, fmt.Sprintf("the answer is longer than %d bytes", c.maxBytes()))
	case rerr != nil:
		return fail(ErrUnavailable, "reading the answer: "+TransportReason(rerr))
	}
	return call, data, nil
}

// observe records whether the DSS answered.
func (c *Client) observe(up bool, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	if !c.known || c.up != up {
		c.since = now
	}
	c.known, c.up, c.reason, c.last = true, up, reason, now
}

// Health is the DSS as the client last saw it.
type Health struct {
	// Known is false before the first call.
	Known bool
	Up    bool
	// Since is when it entered its state; Last the last call.
	Since, Last time.Time
	Reason      string
}

// Health is the client's view of the DSS.
func (c *Client) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Health{Known: c.known, Up: c.up, Since: c.since, Last: c.last, Reason: c.reason}
}

// TransportReason names a transport failure without the URL's query or
// anything the peer sent.
func TransportReason(err error) string {
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
	return clip(err.Error(), 300)
}

// Excerpt is the first limit bytes of b as valid UTF-8, with a note
// when b was longer.
func Excerpt(b []byte, limit int, capped bool) string {
	cut := len(b) > limit
	if cut {
		b = b[:limit]
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	s := strings.ToValidUTF8(string(b), "?")
	switch {
	case capped:
		return s + "... (truncated: the answer is longer than the read bound)"
	case cut:
		return s + "... (truncated)"
	}
	return s
}

// retryAfter reads a Retry-After in delay-seconds, 0 when absent or
// malformed, at most maxWait (0: 60 s).
func retryAfter(v string, maxWait time.Duration) time.Duration {
	if maxWait <= 0 {
		maxWait = time.Minute
	}
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 10 {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	if n > int64(maxWait/time.Second) {
		return maxWait
	}
	return time.Duration(n) * time.Second
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
