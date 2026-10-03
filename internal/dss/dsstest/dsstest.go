// Package dsstest is an in-test DSS and USS subscriber for the tests of
// the F3548 constraint manager (WP-9): the three constraint-reference
// operations of the pinned utm.yaml with their ovn semantics (a create
// of an existing reference and a write at a stale ovn are 409, a write of
// an unknown one 404, each write a new ovn and version), the subscribers
// it is told to name with a notification_index per subscription, outage
// and failure injection, and a record of every request so presence is
// asserted (E-01). Never imported by a process.
package dsstest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rootxkit/uspace-core/f3548"
)

// Request is one request a stub received.
type Request struct {
	Method, Path string
	Header       http.Header
	Body         []byte
	At           time.Time
}

// Subscriber is a USS the DSS names, with its subscription ids.
type Subscriber struct {
	BaseURL       string
	Subscriptions []string
}

type reference struct {
	ovn     string
	version int32
	start   time.Time
	end     time.Time
	base    string
}

// DSS is the in-test DSS. The zero value is not usable; call New.
type DSS struct {
	srv *httptest.Server
	// Manager is the manager the DSS derives from the token (fixed here).
	Manager string

	mu          sync.Mutex
	refs        map[string]*reference
	reqs        []Request
	subscribers []Subscriber
	index       map[string]int32
	// raw, when set, answers the next writes with this body instead.
	raw []string

	// Down makes every request answer 503 (and is recorded).
	Down atomic.Bool
}

// New starts a DSS that names subscribers on every write.
func New(subscribers ...Subscriber) *DSS {
	d := &DSS{Manager: "ansp-01", refs: map[string]*reference{}, index: map[string]int32{}, subscribers: subscribers}
	d.srv = httptest.NewServer(http.HandlerFunc(d.serve))
	return d
}

// URL is the DSS's base URL.
func (d *DSS) URL() string { return d.srv.URL }

// Host is the DSS's host (the aud of its tokens).
func (d *DSS) Host() string { return strings.TrimPrefix(d.srv.URL, "http://") }

// Close stops the server.
func (d *DSS) Close() { d.srv.Close() }

// SetSubscribers replaces the subscribers named on the next writes.
func (d *DSS) SetSubscribers(subs ...Subscriber) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscribers = subs
}

// AnswerRaw makes the next write answer with body (status of the
// operation's success), once per body given.
func (d *DSS) AnswerRaw(bodies ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.raw = append(d.raw, bodies...)
}

// Bump changes the ovn of reference id as another writer would: this
// system's ovn becomes stale. False when there is no such reference.
func (d *DSS) Bump(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.refs[id]
	if !ok {
		return false
	}
	r.ovn, r.version = newOVN(), r.version+1
	return true
}

// OVN is the current ovn of id, "" when it does not exist.
func (d *DSS) OVN(id string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r, ok := d.refs[id]; ok {
		return r.ovn
	}
	return ""
}

// Requests is every request received, oldest first.
func (d *DSS) Requests() []Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Request(nil), d.reqs...)
}

func newOVN() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "ovn-" + hex.EncodeToString(b[:])
}

const prefix = "/dss/v1/constraint_references/"

func (d *DSS) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reqs = append(d.reqs, Request{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body, At: time.Now()})
	if d.Down.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "down (dsstest)"})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok || rest == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "no such path"})
		return
	}
	id, ovn, withOVN := strings.Cut(rest, "/")
	ref, exists := d.refs[id]
	switch {
	case r.Method == http.MethodGet && !withOVN:
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, f3548.GetConstraintReferenceResponse{ConstraintReference: d.wire(id, ref, true)})
	case r.Method == http.MethodPut && !withOVN:
		if exists {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "exists"})
			return
		}
		d.write(w, http.StatusCreated, id, nil, body)
	case r.Method == http.MethodPut && withOVN:
		switch {
		case !exists:
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
		case ref.ovn != ovn:
			writeJSON(w, http.StatusConflict, map[string]string{"message": "stale ovn"})
		default:
			d.write(w, http.StatusOK, id, ref, body)
		}
	case r.Method == http.MethodDelete && withOVN:
		switch {
		case !exists:
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
		case ref.ovn != ovn:
			writeJSON(w, http.StatusConflict, map[string]string{"message": "stale ovn"})
		default:
			delete(d.refs, id)
			if d.answerRaw(w, http.StatusOK) {
				return
			}
			writeJSON(w, http.StatusOK, f3548.ChangeConstraintReferenceResponse{ConstraintReference: d.wire(id, ref, false), Subscribers: d.notify()})
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "not an operation of this stub"})
	}
}

// answerRaw answers with the next raw body, if one was given.
func (d *DSS) answerRaw(w http.ResponseWriter, status int) bool {
	if len(d.raw) == 0 {
		return false
	}
	b := d.raw[0]
	d.raw = d.raw[1:]
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, b)
	return true
}

func (d *DSS) write(w http.ResponseWriter, status int, id string, ref *reference, body []byte) {
	var p f3548.PutConstraintReferenceParameters
	if err := json.Unmarshal(body, &p); err != nil || len(p.Extents) == 0 || p.UssBaseUrl == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "not a PutConstraintReferenceParameters"})
		return
	}
	start, end := time.Time{}, time.Time{}
	for _, e := range p.Extents {
		if e.TimeStart != nil && (start.IsZero() || e.TimeStart.Value.Before(start)) {
			start = e.TimeStart.Value
		}
		if e.TimeEnd != nil && e.TimeEnd.Value.After(end) {
			end = e.TimeEnd.Value
		}
	}
	if ref == nil {
		ref = &reference{}
		d.refs[id] = ref
	}
	ref.ovn, ref.version, ref.start, ref.end, ref.base = newOVN(), ref.version+1, start, end, p.UssBaseUrl
	if d.answerRaw(w, status) {
		return
	}
	writeJSON(w, status, f3548.ChangeConstraintReferenceResponse{ConstraintReference: d.wire(id, ref, true), Subscribers: d.notify()})
}

func (d *DSS) wire(id string, ref *reference, withOVN bool) f3548.ConstraintReference {
	out := f3548.ConstraintReference{Id: id, Manager: d.Manager, UssAvailability: "Unknown", UssBaseUrl: ref.base, Version: ref.version,
		TimeStart: f3548.Time{Format: f3548.RFC3339, Value: ref.start}, TimeEnd: f3548.Time{Format: f3548.RFC3339, Value: ref.end}}
	if withOVN {
		o := ref.ovn
		out.Ovn = &o
	}
	return out
}

// notify is the subscribers of a write, each subscription's index moved
// on by one.
func (d *DSS) notify() []f3548.SubscriberToNotify {
	out := make([]f3548.SubscriberToNotify, 0, len(d.subscribers))
	for _, s := range d.subscribers {
		n := f3548.SubscriberToNotify{UssBaseUrl: s.BaseURL}
		for _, id := range s.Subscriptions {
			d.index[id]++
			n.Subscriptions = append(n.Subscriptions, f3548.SubscriptionState{SubscriptionId: id, NotificationIndex: d.index[id]})
		}
		out = append(out, n)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// USS is an in-test subscriber: it records every request and answers
// with Answer (204 by default, the standard's success).
type USS struct {
	srv *httptest.Server

	mu   sync.Mutex
	reqs []Request
	// answer is the status of the n-th request (1-based).
	answer func(n int, r Request) int
}

// NewUSS starts a subscriber.
func NewUSS() *USS {
	u := &USS{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		rec := Request{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body, At: time.Now()}
		u.mu.Lock()
		u.reqs = append(u.reqs, rec)
		n, answer := len(u.reqs), u.answer
		u.mu.Unlock()
		code := http.StatusNoContent
		if answer != nil {
			code = answer(n, rec)
		}
		w.WriteHeader(code)
	}))
	return u
}

// URL is the subscriber's uss_base_url.
func (u *USS) URL() string { return u.srv.URL }

// Host is the subscriber's host (the aud of the tokens it is sent).
func (u *USS) Host() string { return strings.TrimPrefix(u.srv.URL, "http://") }

// Close stops the server.
func (u *USS) Close() { u.srv.Close() }

// Answer sets how the subscriber answers.
func (u *USS) Answer(f func(n int, r Request) int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.answer = f
}

// Requests is every request received, oldest first.
func (u *USS) Requests() []Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Request(nil), u.reqs...)
}
