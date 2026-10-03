package dss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/auth"
)

// Subscriber is one USS the DSS named, with every subscription of it
// that prompted the notification (one notification per uss_base_url).
type Subscriber struct {
	USSBaseURL    string
	Subscriptions []f3548.SubscriptionState
}

// Subscribers groups the DSS's list by uss_base_url (without a trailing
// '/'), in the order first named, each subscription once: a USS named
// twice gets one notification carrying both subscriptions.
func Subscribers(list []f3548.SubscriberToNotify) []Subscriber {
	var out []Subscriber
	at := map[string]int{}
	seen := map[string]bool{}
	for _, s := range list {
		base := strings.TrimRight(s.UssBaseUrl, "/")
		i, ok := at[base]
		if !ok {
			i = len(out)
			at[base] = i
			out = append(out, Subscriber{USSBaseURL: base})
		}
		for _, sub := range s.Subscriptions {
			key := base + "\x00" + strings.ToLower(sub.SubscriptionId)
			if seen[key] {
				continue
			}
			seen[key] = true
			out[i].Subscriptions = append(out[i].Subscriptions, sub)
		}
	}
	return out
}

// NotificationBody is the PutConstraintDetailsParameters of a change of
// constraint id: on a write the full Constraint (reference with its ovn,
// and details); on a deletion (constraint nil) the constraint omitted,
// as the standard says.
func NotificationBody(id string, constraint *f3548.Constraint, subs []f3548.SubscriptionState) ([]byte, error) {
	if len(subs) == 0 {
		return nil, errors.New("a notification needs the subscriptions that prompted it")
	}
	if constraint != nil && constraint.Reference.Ovn == nil {
		return nil, errors.New("the reference of a notified constraint must carry its ovn")
	}
	return json.Marshal(f3548.PutConstraintDetailsParameters{Constraint: constraint, ConstraintId: id, Subscriptions: subs})
}

// Notifier posts a notification to a subscriber: POST
// {uss_base_url}/uss/v1/constraints with a token of the operation's
// scope (utm.constraint_management, as the pinned standard secures
// notifyConstraintDetailsChanged) whose aud is the host of that
// uss_base_url as the DSS returned it (M18: peers are discovered, never
// mapped through a configured list).
type Notifier struct {
	HTTP         *http.Client
	Tokens       Tokens
	ExcerptBytes int
	// MaxResponseBytes bounds what is read of an answer.
	MaxResponseBytes int
	// AllowPrivate lets a notification go to http and to a loopback,
	// private, link-local or otherwise non-public address
	// (ANSP_DSS_NOTIFY_PRIVATE_ALLOWED, the lab and tests only). Without
	// it a uss_base_url, which any DSS participant writes, must be https
	// on a public address, and HTTP's transport should carry
	// GuardTransport so the resolved address is checked at dial time.
	AllowPrivate bool
}

// ErrTargetRefused is a notification target that is not https on a
// public address while private targets are not allowed.
var ErrTargetRefused = errors.New("the subscriber's uss_base_url is not https on a public address")

// publicAddr is whether a is a public unicast address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!cgnat.Contains(a) && !a.IsMulticast() && !a.IsUnspecified()
}

// cgnat is RFC 6598 shared address space, not routed publicly.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// refuseNonPublic is a net.Dialer Control: a connection to an address
// that is not public is refused before it is made.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !publicAddr(ap.Addr()) {
		return fmt.Errorf("%w (dialled %s)", ErrTargetRefused, address)
	}
	return nil
}

// GuardTransport makes c's transport refuse, at dial time, every address
// that is not public: a uss_base_url whose name resolves to a loopback
// or private address is refused as its literal would be (ansp audit S-2).
func GuardTransport(c *http.Client) {
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	}
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseNonPublic}
	tr.DialContext = d.DialContext
	tr.Proxy = nil
	c.Transport = tr
}

// checkTarget refuses a base that is not https, or whose host is an
// address literal that is not public, unless AllowPrivate.
func (n *Notifier) checkTarget(base string) error {
	if n.AllowPrivate {
		return nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" {
		return ErrTargetRefused
	}
	if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && !publicAddr(a) {
		return ErrTargetRefused
	}
	if strings.EqualFold(u.Hostname(), "localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost") {
		return ErrTargetRefused
	}
	return nil
}

// Notify sends body to the subscriber at base; the Call says what was
// answered (204 is the standard's success).
func (n *Notifier) Notify(ctx context.Context, base string, body []byte) Call {
	op := Op(OpNotifyDetails)
	call := Call{Method: op.Method, Path: NotifyPath()}
	if err := checkBaseURL("uss_base_url", base); err != nil {
		call.Err = "target: " + err.Error()
		return call
	}
	if err := n.checkTarget(base); err != nil {
		call.Err, call.Refused = "target: "+err.Error(), true
		return call
	}
	aud, err := auth.AudienceOf(base)
	if err != nil {
		call.Err = "target: " + err.Error()
		return call
	}
	if n.Tokens == nil {
		call.Err = "no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE)"
		return call
	}
	tok, err := n.Tokens.TokenFor(ctx, aud, []string{op.Scope()})
	if err != nil {
		call.Err = "token: " + clip(err.Error(), 300)
		return call
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, strings.TrimRight(base, "/")+NotifyPath(), bytes.NewReader(body))
	if err != nil {
		call.Err = "request: " + clip(err.Error(), 300)
		return call
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, ErrTargetRefused) {
			call.Err, call.Refused = "target: "+ErrTargetRefused.Error(), true
			return call
		}
		call.Err = TransportReason(err)
		return call
	}
	defer func() { _ = resp.Body.Close() }()
	limit := n.MaxResponseBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	ex := n.ExcerptBytes
	if ex <= 0 {
		ex = 1024
	}
	call.Status = resp.StatusCode
	call.Excerpt = Excerpt(data, ex, len(data) > limit)
	call.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), 0)
	return call
}
