package cis

import (
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
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
)

// ScopeCISRead is the scope of every call to the CISP (spec 06 section 3).
const ScopeCISRead = "cis.read"

// Client defaults.
const (
	// DefaultTimeout is the deadline of one call.
	DefaultTimeout = 15 * time.Second
	// MaxErrorBodyBytes is how much of an error answer is read.
	MaxErrorBodyBytes = 8 << 10
	// MaxSmallBodyBytes bounds an answer that is not a dataset (a
	// subscription, a list of them).
	MaxSmallBodyBytes = 1 << 20
)

// The response headers of the CISP's dataset reads (api/clients/cisp.yaml).
const (
	HeaderVersion            = "X-CIS-Version"
	HeaderStale              = "X-CIS-Stale"
	HeaderPublisherSignature = "X-Publisher-Signature"
	HeaderPublisherKID       = "X-Publisher-Kid"
)

// TokenSource hands out an ecosystem token whose aud is the host of
// baseURL with the scopes (internal/auth.TokenSource, M18).
type TokenSource interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// ErrNoTokenSource is every call of a Client without a token source: the
// CISP refuses an unauthenticated read, and the status says why.
var ErrNoTokenSource = errors.New("no token client for the CISP (ANSP_TOKEN_URL and ANSP_CLIENT_SECRET_FILE)")

// ClientConfig configures a Client.
type ClientConfig struct {
	// BaseURL is ANSP_CISP_URL.
	BaseURL string
	Tokens  TokenSource
	// HTTPClient is used for every call; nil is a client that never
	// follows a redirect (a 3xx is an error).
	HTTPClient *http.Client
	Timeout    time.Duration
}

// Client calls the CISP's F3 API through the generated client of the
// pinned api/clients/cisp.yaml. Every call has a deadline, carries a
// cis.read token whose aud is the CISP's host, and reads a bounded body.
type Client struct {
	cfg  ClientConfig
	base *url.URL
	gen  *cispclient.Client
}

// NewClient builds a Client; a base URL that is not an absolute http(s)
// URL is a *core.FieldError on ANSP_CISP_URL.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, core.Fieldf("ANSP_CISP_URL", "not an absolute http(s) URL without user information")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	c := &Client{cfg: cfg, base: u}
	c.gen, err = cispclient.NewClient(strings.TrimRight(cfg.BaseURL, "/"), cispclient.WithHTTPClient(cfg.HTTPClient),
		cispclient.WithRequestEditorFn(c.authorise))
	if err != nil {
		return nil, fmt.Errorf("CISP client: %w", err)
	}
	return c, nil
}

// Host is the configured CISP's host without its port.
func (c *Client) Host() string { return c.base.Hostname() }

func (c *Client) authorise(ctx context.Context, req *http.Request) error {
	if c.cfg.Tokens == nil {
		return ErrNoTokenSource
	}
	tok, err := c.cfg.Tokens.Token(ctx, c.cfg.BaseURL, ScopeCISRead)
	if err != nil {
		return fmt.Errorf("token for the CISP: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// StatusError is an answer of the CISP other than the ones a call
// expects: its status and the problem's type slug, when it sent one.
type StatusError struct {
	Status int
	Slug   string
	Detail string
}

func (e *StatusError) Error() string {
	s := "the CISP answered " + strconv.Itoa(e.Status)
	if e.Slug != "" {
		s += " " + e.Slug
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func statusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	e := &StatusError{Status: resp.StatusCode}
	var p cispclient.Problem
	if json.Unmarshal(body, &p) == nil {
		if i := strings.LastIndex(p.Type, "/"); i >= 0 {
			e.Slug = short(p.Type[i+1:])
		}
		if p.Detail != nil {
			e.Detail = short(*p.Detail)
		}
	}
	return e
}

// Fetched is one answer to a dataset read.
type Fetched struct {
	// Status is 200, 304 (If-None-Match named the current version) or
	// 404 (the dataset has no version yet: the problem no_version).
	Status int
	ETag   string
	// Version is X-CIS-Version (0 when absent).
	Version int64
	// Stale is X-CIS-Stale: the CISP served the snapshot it holds
	// because its database cannot be reached.
	Stale bool
	Body  []byte
	// PublisherSignature and PublisherKID are X-Publisher-Signature and
	// X-Publisher-Kid ("" when absent; only a version read sends them).
	PublisherSignature string
	PublisherKID       string
}

// GetDataset is GET /v1/{dataset}, unfiltered, with If-None-Match etag
// when it is not empty: the projection stores what the CISP serves
// whole, never a filtered or delta answer.
func (c *Client) GetDataset(ctx context.Context, d Dataset, etag string) (Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	p := &cispclient.GetDatasetParams{}
	if etag != "" {
		p.IfNoneMatch = &etag
	}
	resp, err := c.gen.GetDataset(ctx, cispclient.GetDatasetParamsDataset(d), p)
	if err != nil {
		return Fetched{}, err
	}
	return c.read(resp)
}

// GetVersion is GET /v1/{dataset}/versions/{v}: one version as its
// publisher sent it, with the publisher's detached JWS.
func (c *Client) GetVersion(ctx context.Context, d Dataset, v int64) (Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.GetDatasetVersion(ctx, cispclient.GetDatasetVersionParamsDataset(d), v, &cispclient.GetDatasetVersionParams{})
	if err != nil {
		return Fetched{}, err
	}
	return c.read(resp)
}

func (c *Client) read(resp *http.Response) (Fetched, error) {
	defer func() { _ = resp.Body.Close() }()
	f := Fetched{
		Status: resp.StatusCode, ETag: resp.Header.Get("ETag"), Stale: resp.Header.Get(HeaderStale) == "true",
		PublisherSignature: resp.Header.Get(HeaderPublisherSignature), PublisherKID: resp.Header.Get(HeaderPublisherKID),
	}
	if v := resp.Header.Get(HeaderVersion); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return Fetched{}, errors.New(HeaderVersion + " is not a version")
		}
		f.Version = n
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return f, nil
	case http.StatusNotFound:
		err := statusError(resp)
		var se *StatusError
		if errors.As(err, &se) && se.Slug == "no_version" {
			return f, nil
		}
		return Fetched{}, err
	default:
		return Fetched{}, statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDatasetBytes+1))
	if err != nil {
		return Fetched{}, fmt.Errorf("reading the answer: %w", err)
	}
	if len(body) > MaxDatasetBytes {
		return Fetched{}, &TooLargeError{Limit: MaxDatasetBytes}
	}
	f.Body = body
	return f, nil
}

// TooLargeError is an answer longer than the bound: refused before it
// is parsed (E-10).
type TooLargeError struct{ Limit int }

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("the answer is longer than %d bytes", e.Limit)
}

func (c *Client) decode(resp *http.Response, want int, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		return statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSmallBodyBytes+1))
	if err != nil {
		return fmt.Errorf("reading the answer: %w", err)
	}
	if len(body) > MaxSmallBodyBytes {
		return &TooLargeError{Limit: MaxSmallBodyBytes}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("the answer does not decode: %s", short(err.Error()))
	}
	return nil
}

// ErrSubscriptionUnknown is the CISP saying 404 for a subscription id:
// it was deleted, or the CISP's database was recreated.
var ErrSubscriptionUnknown = errors.New("the CISP does not know the subscription")

// GetSubscription is GET /v1/subscriptions/{id}.
func (c *Client) GetSubscription(ctx context.Context, id string) (cispclient.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.GetSubscription(ctx, id)
	if err != nil {
		return cispclient.Subscription{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return cispclient.Subscription{}, ErrSubscriptionUnknown
	}
	var out cispclient.Subscription
	err = c.decode(resp, http.StatusOK, &out)
	return out, err
}

// Subscribe makes sure this system holds one subscription with callback
// for datasets, and returns it. It is idempotent, so a restart never
// adds a subscription (the CISP holds at most 20 per client): it lists
// the caller's subscriptions and reuses the one with the same callback,
// patching it when its datasets differ or it is suspended (a PATCH
// re-activates it); only when there is none does it create one.
func (c *Client) Subscribe(ctx context.Context, callback string, datasets []Dataset) (cispclient.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.ListSubscriptions(ctx)
	if err != nil {
		return cispclient.Subscription{}, err
	}
	var list cispclient.SubscriptionList
	if err := c.decode(resp, http.StatusOK, &list); err != nil {
		return cispclient.Subscription{}, err
	}
	want := make([]string, len(datasets))
	for i, d := range datasets {
		want[i] = string(d)
	}
	slices.Sort(want)
	for i := range list.Subscriptions {
		s := &list.Subscriptions[i]
		if s.CallbackUrl != callback || s.Status == cispclient.SubscriptionStatusDeleted {
			continue
		}
		have := make([]string, len(s.Datasets))
		for i, d := range s.Datasets {
			have[i] = string(d)
		}
		slices.Sort(have)
		if slices.Equal(have, want) && s.Status != cispclient.SubscriptionStatusSuspended {
			return *s, nil
		}
		return c.patch(ctx, s.Id, datasets)
	}
	ds := make([]cispclient.SubscriptionCreateDatasets, len(datasets))
	for i, d := range datasets {
		ds[i] = cispclient.SubscriptionCreateDatasets(d)
	}
	resp, err = c.gen.CreateSubscription(ctx, cispclient.SubscriptionCreate{CallbackUrl: callback, Datasets: ds})
	if err != nil {
		return cispclient.Subscription{}, err
	}
	var out cispclient.Subscription
	err = c.decode(resp, http.StatusCreated, &out)
	return out, err
}

// Reactivate is PATCH /v1/subscriptions/{id} with the datasets: the
// CISP pings a suspended subscription again and activates it on the
// first 2xx.
func (c *Client) Reactivate(ctx context.Context, id string, datasets []Dataset) (cispclient.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	return c.patch(ctx, id, datasets)
}

func (c *Client) patch(ctx context.Context, id string, datasets []Dataset) (cispclient.Subscription, error) {
	ds := make([]cispclient.SubscriptionPatchDatasets, len(datasets))
	for i, d := range datasets {
		ds[i] = cispclient.SubscriptionPatchDatasets(d)
	}
	resp, err := c.gen.PatchSubscription(ctx, id, cispclient.SubscriptionPatch{Datasets: &ds})
	if err != nil {
		return cispclient.Subscription{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return cispclient.Subscription{}, ErrSubscriptionUnknown
	}
	var out cispclient.Subscription
	err = c.decode(resp, http.StatusOK, &out)
	return out, err
}

// ErrPullURLRefused is a pull_url this system will not follow.
var ErrPullURLRefused = errors.New("pull_url refused")

// CheckPullURL says whether raw is on the configured CISP: an absolute
// https URL (plain http never, even when ANSP_CISP_URL is http) with the
// CISP's host and port (a missing port is the scheme's default) and no
// user information (M5, the SSRF guard).
func (c *Client) CheckPullURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return fmt.Errorf("%w: not an absolute URL", ErrPullURLRefused)
	case u.Scheme != "https":
		return fmt.Errorf("%w: scheme %q, only https is followed", ErrPullURLRefused, short(u.Scheme))
	case u.Scheme != c.base.Scheme:
		return fmt.Errorf("%w: the CISP is configured on %q", ErrPullURLRefused, c.base.Scheme)
	case u.User != nil:
		return fmt.Errorf("%w: it carries user information", ErrPullURLRefused)
	case !strings.EqualFold(u.Hostname(), c.base.Hostname()):
		return fmt.Errorf("%w: host %q is not the CISP's", ErrPullURLRefused, short(u.Hostname()))
	case effectivePort(u) != effectivePort(c.base):
		return fmt.Errorf("%w: port %s, the CISP's is %s", ErrPullURLRefused, short(effectivePort(u)), effectivePort(c.base))
	}
	return nil
}

// effectivePort is u's port, or its scheme's default.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
