package auth

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// Defaults of TokenSourceConfig.
const (
	DefaultTokenEntries      = 64
	DefaultTokenFetchTimeout = 5 * time.Second
	DefaultTokenMaxBodyBytes = 64 << 10
	DefaultTokenAttempts     = 3
	DefaultTokenBackoff      = 200 * time.Millisecond
	// MaxTokenTTL bounds the expires_in the source believes.
	MaxTokenTTL = time.Hour
)

// Counters of the TokenSource (brief WP-2).
//
//nolint:gosec // counter names, not credentials
const (
	CounterTokenFetchOK     = "token_fetch_ok"
	CounterTokenFetchFailed = "token_fetch_failed"
	CounterTokenCachedUsed  = "token_cached_during_outage"
	CounterTokenEvicted     = "token_cache_evicted"
)

// TokenSourceConfig configures a TokenSource.
type TokenSourceConfig struct {
	// TokenURL is ANSP_TOKEN_URL, the authority's POST /oauth/token.
	TokenURL string
	// ClientID is ansp-01 (M24); ClientSecret the content of
	// ANSP_CLIENT_SECRET_FILE.
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Now          func() time.Time
	// MaxEntries bounds the cached tokens, one per (aud, scope set).
	MaxEntries int
	// FetchTimeout bounds one token request.
	FetchTimeout time.Duration
	MaxBodyBytes int64
	// Attempts bounds the tries of one fetch (transport errors and 5xx
	// only); Backoff is the wait before the second, doubled after.
	Attempts int
	Backoff  time.Duration
}

// TokenSourceFromConfig is the configuration of cfg's outbound client.
func TokenSourceFromConfig(cfg config.Config) TokenSourceConfig {
	return TokenSourceConfig{TokenURL: cfg.TokenURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}
}

// AudienceOf is the one place a target's audience is derived (M18): the
// host of its base URL, lower-case, with an explicit port kept (the aud
// a peer verifies is its ANSP_AUDIENCES-style host entry) and the path,
// query and user information dropped.
func AudienceOf(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", core.Fieldf("base_url", "not an absolute http(s) URL")
	}
	return strings.ToLower(u.Host), nil
}

// TokenSource fetches client-credentials tokens for this system's calls
// to the CISP, the DSS, the USSPs and the authority (06 section 3): as
// client ansp-01, with the audience parameter set to the host of the
// target's base URL (M18), one token per (aud, scope set). A token is
// refreshed in the background from half its lifetime on (06 T5) while
// the cached one keeps being handed out; during an issuer outage the
// cached token is used until its exp (counted). A call without a usable
// token joins the fetch in flight for its key, or starts it, and waits
// for it or for its own context; the fetch runs on a context of its own
// with bounded retries, so a cancelled caller never fails it for the
// others (E-14). Safe for concurrent use; errors never carry a token or
// the secret.
type TokenSource struct {
	cfg      TokenSourceConfig
	counters core.Counters

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = most recently used
}

type tokenEntry struct {
	key      string
	audience string
	scopes   []string
	token    string
	issued   time.Time
	expires  time.Time
	inflight chan struct{}
	err      error
}

// NewTokenSource validates c and applies the defaults.
func NewTokenSource(c TokenSourceConfig) (*TokenSource, error) {
	u, err := url.Parse(c.TokenURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, core.Fieldf("ANSP_TOKEN_URL", "not an absolute http(s) URL")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, core.Fieldf("ANSP_CLIENT_SECRET_FILE", "the client id and secret are required for outbound calls")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = DefaultTokenEntries
	}
	if c.FetchTimeout <= 0 {
		c.FetchTimeout = DefaultTokenFetchTimeout
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultTokenMaxBodyBytes
	}
	if c.Attempts <= 0 {
		c.Attempts = DefaultTokenAttempts
	}
	if c.Backoff <= 0 {
		c.Backoff = DefaultTokenBackoff
	}
	return &TokenSource{cfg: c, entries: map[string]*list.Element{}, order: list.New()}, nil
}

// Counters are the source's counters.
func (s *TokenSource) Counters() *core.Counters { return &s.counters }

// Len is the number of cached entries.
func (s *TokenSource) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// Token returns a token to call the system published at baseURL with
// every one of scopes.
func (s *TokenSource) Token(ctx context.Context, baseURL string, scopes ...string) (string, error) {
	aud, err := AudienceOf(baseURL)
	if err != nil {
		return "", err
	}
	return s.TokenFor(ctx, aud, scopes)
}

// TokenFor returns a token for audience (a host) and scopes.
func (s *TokenSource) TokenFor(ctx context.Context, audience string, scopes []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if audience == "" || len(sorted) == 0 || slices.Contains(sorted, "") {
		return "", core.Fieldf("scope", "an audience and at least one non-empty scope")
	}
	key := audience + " " + strings.Join(sorted, " ")

	s.mu.Lock()
	e := s.lookup(key, audience, sorted)
	now := s.cfg.Now()
	if e.token != "" && now.Before(e.expires) {
		tok := e.token
		if e.inflight == nil && !now.Before(e.issued.Add(e.expires.Sub(e.issued)/2)) {
			s.start(e) // refresh in the background from half the lifetime on
		}
		if e.err != nil {
			s.counters.Inc(CounterTokenCachedUsed)
		}
		s.mu.Unlock()
		return tok, nil
	}
	done := e.inflight
	if done == nil {
		done = s.start(e)
	}
	s.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.token != "" && s.cfg.Now().Before(e.expires) {
		return e.token, nil
	}
	if e.err != nil {
		return "", e.err
	}
	return "", errors.New("the token service answered a token that has already expired")
}

// lookup returns the entry of key, creating it and evicting the least
// recently used entry with no fetch in flight beyond the bound. The
// caller holds mu.
func (s *TokenSource) lookup(key, audience string, scopes []string) *tokenEntry {
	if el, ok := s.entries[key]; ok {
		s.order.MoveToFront(el)
		return el.Value.(*tokenEntry)
	}
	for s.order.Len() >= s.cfg.MaxEntries {
		victim := s.order.Back()
		for victim != nil && victim.Value.(*tokenEntry).inflight != nil {
			victim = victim.Prev()
		}
		if victim == nil {
			break
		}
		s.order.Remove(victim)
		delete(s.entries, victim.Value.(*tokenEntry).key)
		s.counters.Inc(CounterTokenEvicted)
	}
	e := &tokenEntry{key: key, audience: audience, scopes: scopes}
	s.entries[key] = s.order.PushFront(e)
	return e
}

// start launches the fetch of e on a context of its own; the caller
// holds mu.
func (s *TokenSource) start(e *tokenEntry) chan struct{} {
	done := make(chan struct{})
	e.inflight = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Attempts)*s.cfg.FetchTimeout)
		defer cancel()
		tok, ttl, err := s.fetchWithRetry(ctx, e.audience, e.scopes)
		now := s.cfg.Now()
		s.mu.Lock()
		if err != nil {
			s.counters.Inc(CounterTokenFetchFailed)
			e.err = err
		} else {
			s.counters.Inc(CounterTokenFetchOK)
			e.token, e.issued, e.expires, e.err = tok, now, now.Add(ttl), nil
		}
		e.inflight = nil
		s.mu.Unlock()
		close(done)
	}()
	return done
}

// retryable is a failure worth another attempt: the token service did
// not answer, or answered 5xx.
func retryable(err error) bool {
	var tse *TokenServiceError
	if errors.As(err, &tse) {
		return tse.Status >= 500
	}
	return errors.Is(err, errUnreachable)
}

func (s *TokenSource) fetchWithRetry(ctx context.Context, audience string, scopes []string) (string, time.Duration, error) {
	wait := s.cfg.Backoff
	var err error
	for attempt := 1; ; attempt++ {
		var tok string
		var ttl time.Duration
		actx, cancel := context.WithTimeout(ctx, s.cfg.FetchTimeout)
		tok, ttl, err = s.fetch(actx, audience, scopes)
		cancel()
		if err == nil {
			return tok, ttl, nil
		}
		if attempt >= s.cfg.Attempts || !retryable(err) {
			return "", 0, err
		}
		select {
		case <-ctx.Done():
			return "", 0, err
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// TokenServiceError is a refused token request: the issuer's RFC 6749
// error. It never carries a token or the secret.
type TokenServiceError struct {
	Status      int
	Code        string
	Description string
}

func (e *TokenServiceError) Error() string {
	return fmt.Sprintf("token request refused (%d %s): %s", e.Status, e.Code, e.Description)
}

var errUnreachable = errors.New("token request: the token service did not answer")

func (s *TokenSource) fetch(ctx context.Context, audience string, scopes []string) (string, time.Duration, error) {
	// client_secret_post: the method the authority's token service
	// supports (its metadata lists client_secret_post and
	// private_key_jwt).
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(scopes, " ")}, "audience": {audience},
		"client_id": {s.cfg.ClientID}, "client_secret": {s.cfg.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, errUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		return "", 0, errUnreachable
	}
	if int64(len(body)) > s.cfg.MaxBodyBytes {
		return "", 0, fmt.Errorf("token response larger than %d bytes", s.cfg.MaxBodyBytes)
	}
	return ParseTokenResponse(resp.StatusCode, body)
}

// clipText bounds a value from a peer before it reaches an error.
func clipText(v string) string {
	v = strings.ToValidUTF8(v, "?")
	for len(v) > 200 {
		v = v[:200]
		for len(v) > 0 && !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// ParseTokenResponse reads an RFC 6749 section 5.1 answer (or a section
// 5.2 refusal): a Bearer token and a positive integer expires_in of at
// most MaxTokenTTL. The errors never contain the token.
func ParseTokenResponse(status int, body []byte) (string, time.Duration, error) {
	if status != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = "http_" + strconv.Itoa(status)
		}
		return "", 0, &TokenServiceError{Status: status, Code: clipText(e.Error), Description: clipText(e.Description)}
	}
	var r struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", 0, errors.New("token response is not a JSON object")
	}
	if r.AccessToken == "" || len(r.AccessToken) > coreauth.DefaultMaxTokenBytes {
		return "", 0, errors.New("token response has no usable access_token")
	}
	if !strings.EqualFold(r.TokenType, "Bearer") {
		return "", 0, errors.New("token response is not a Bearer token")
	}
	secs, err := strconv.ParseInt(string(r.ExpiresIn), 10, 64)
	if err != nil || secs <= 0 || secs > int64(MaxTokenTTL/time.Second) {
		return "", 0, fmt.Errorf("token response expires_in is not a positive integer of at most %d", int64(MaxTokenTTL/time.Second))
	}
	return r.AccessToken, time.Duration(secs) * time.Second, nil
}
