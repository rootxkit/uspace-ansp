package dss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

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
