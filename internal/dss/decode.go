package dss

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// Bounds of what is read from a DSS answer (E-10). The answer's byte
// bound and the subscriber bound are the caller's policy.
const (
	// MaxOVNBytes bounds an ovn (it becomes a path segment and a column).
	MaxOVNBytes = 256
	// MaxURLBytes bounds a uss_base_url (deliveries.target holds 512).
	MaxURLBytes = 512
	// MaxManagerBytes bounds the manager the DSS derives from our token.
	MaxManagerBytes = 256
)

// ErrTooManySubscribers is an answer naming more subscribers (or more
// subscriptions) than the policy's bound: refused whole, never cut, so a
// subscriber is never silently left out.
var ErrTooManySubscribers = errors.New("more subscribers than the bound")

// DecodeChange reads a ChangeConstraintReferenceResponse (the answer of
// PUT and DELETE) for constraint id from untrusted bytes: one JSON value
// of at most maxBytes, unknown members ignored (spec 02 section 1), then
// the members a delivery rests on checked: the reference's id is id, its
// times are RFC3339 in order, its manager, version, availability and
// uss_base_url present; with needOVN its ovn present and bounded; at most
// maxSubscribers subscriptions over all subscribers, each subscriber an
// absolute http(s) uss_base_url with at least one subscription, each
// subscription a UUID with a non-negative notification_index. Anything
// else is a *core.FieldError naming the member. It never panics
// (FuzzDecodeChange).
func DecodeChange(data []byte, id string, needOVN bool, maxBytes, maxSubscribers int) (f3548.ChangeConstraintReferenceResponse, error) {
	var out f3548.ChangeConstraintReferenceResponse
	if err := decode(data, maxBytes, &out); err != nil {
		return out, err
	}
	if err := checkReference("constraint_reference", out.ConstraintReference, id, needOVN); err != nil {
		return out, err
	}
	if out.Subscribers == nil {
		return out, core.Fieldf("subscribers", "is required")
	}
	if len(out.Subscribers) > maxSubscribers {
		return out, errors.Join(ErrTooManySubscribers, core.Fieldf("subscribers", "names %d subscribers; at most %d", len(out.Subscribers), maxSubscribers))
	}
	total := 0
	for i := range out.Subscribers {
		s := &out.Subscribers[i]
		path := "subscribers[" + strconv.Itoa(i) + "]"
		if err := checkBaseURL(path+".uss_base_url", s.UssBaseUrl); err != nil {
			return out, err
		}
		if len(s.Subscriptions) == 0 {
			return out, core.Fieldf(path+".subscriptions", "is empty")
		}
		total += len(s.Subscriptions)
		if total > maxSubscribers {
			return out, errors.Join(ErrTooManySubscribers, core.Fieldf("subscribers", "name more than %d subscriptions", maxSubscribers))
		}
		for j, sub := range s.Subscriptions {
			sp := path + ".subscriptions[" + strconv.Itoa(j) + "]"
			if _, err := uuid.Parse(sub.SubscriptionId); err != nil || len(sub.SubscriptionId) != 36 {
				return out, core.Fieldf(sp+".subscription_id", "is not a UUID")
			}
			if sub.NotificationIndex < 0 {
				return out, core.Fieldf(sp+".notification_index", "is negative")
			}
		}
	}
	return out, nil
}

// DecodeReference reads a GetConstraintReferenceResponse for id, with
// the checks of DecodeChange's reference; ovn may be absent (the caller
// decides whether it needs one).
func DecodeReference(data []byte, id string, maxBytes int) (f3548.ConstraintReference, error) {
	var out f3548.GetConstraintReferenceResponse
	if err := decode(data, maxBytes, &out); err != nil {
		return f3548.ConstraintReference{}, err
	}
	if err := checkReference("constraint_reference", out.ConstraintReference, id, false); err != nil {
		return f3548.ConstraintReference{}, err
	}
	return out.ConstraintReference, nil
}

// decode reads one JSON value of at most maxBytes into v.
func decode(data []byte, maxBytes int, v any) error {
	if len(data) == 0 {
		return core.Fieldf("body", "is empty")
	}
	if len(data) > maxBytes {
		return core.Fieldf("body", "is %d bytes; at most %d", len(data), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return core.Fieldf(te.Field, "has the wrong JSON type")
		}
		return core.Fieldf("body", "is not the JSON object the standard describes")
	}
	if dec.More() {
		return core.Fieldf("body", "has trailing data")
	}
	return nil
}

func checkReference(path string, r f3548.ConstraintReference, id string, needOVN bool) error {
	if !strings.EqualFold(r.Id, id) {
		return core.Fieldf(path+".id", "is not the constraint written")
	}
	if r.Manager == "" || len(r.Manager) > MaxManagerBytes || !utf8.ValidString(r.Manager) {
		return core.Fieldf(path+".manager", "is empty or longer than %d bytes", MaxManagerBytes)
	}
	if r.Version < 0 {
		return core.Fieldf(path+".version", "is negative")
	}
	if !r.UssAvailability.Valid() {
		return core.Fieldf(path+".uss_availability", "is not Unknown, Normal or Down")
	}
	if err := checkBaseURL(path+".uss_base_url", r.UssBaseUrl); err != nil {
		return err
	}
	if r.TimeStart.Format != f3548.RFC3339 || r.TimeStart.Value.IsZero() {
		return core.Fieldf(path+".time_start", "is not an RFC3339 time")
	}
	if r.TimeEnd.Format != f3548.RFC3339 || r.TimeEnd.Value.IsZero() {
		return core.Fieldf(path+".time_end", "is not an RFC3339 time")
	}
	if r.TimeEnd.Value.Before(r.TimeStart.Value) {
		return core.Fieldf(path+".time_end", "is before time_start")
	}
	if r.Ovn != nil && (*r.Ovn == "" || len(*r.Ovn) > MaxOVNBytes || !utf8.ValidString(*r.Ovn)) {
		return core.Fieldf(path+".ovn", "is empty or longer than %d bytes", MaxOVNBytes)
	}
	if needOVN && r.Ovn == nil {
		return core.Fieldf(path+".ovn", "is required: this system manages the constraint")
	}
	return nil
}

// checkBaseURL accepts an absolute http(s) URL without query or
// fragment, at most MaxURLBytes.
func checkBaseURL(path, s string) error {
	if s == "" || len(s) > MaxURLBytes {
		return core.Fieldf(path, "is empty or longer than %d bytes", MaxURLBytes)
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return core.Fieldf(path, "is not an absolute http(s) URL")
	}
	return nil
}
