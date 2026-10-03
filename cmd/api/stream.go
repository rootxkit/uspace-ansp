package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Bounds of the console stream (E-10).
const (
	// MaxStreamClients bounds the open connections of one api process.
	MaxStreamClients = 64
	// StreamSendBuffer bounds the frames queued for one client; past it a
	// frame is dropped for that client and counted (dropped_frames).
	StreamSendBuffer = 256
	// StreamReadLimit bounds one client frame (console/subscribe/v1).
	StreamReadLimit = 4 << 10
	// StreamSnapshotLimit bounds the restrictions of a snapshot per state.
	StreamSnapshotLimit = 500
	// StreamStatusPeriod is the console/status/v1 period (M29: 2 s).
	StreamStatusPeriod = 2 * time.Second
	// streamWriteTimeout bounds one frame's write.
	streamWriteTimeout = 5 * time.Second
	// streamDedupe bounds the remembered (restriction, version) keys.
	streamDedupe = 4096
	// StreamResubscribeEvery bounds the snapshots one connection's
	// console/subscribe/v1 frames cause (ansp audit S-4).
	StreamResubscribeEvery = time.Second
)

// Counters of the stream.
const (
	CounterStreamRefusedFull = "restriction_stream_refused_full"
	CounterStreamDropped     = "restriction_stream_dropped_frames"
	CounterStreamDuplicates  = "restriction_stream_duplicates"
	CounterStreamClientFrame = "restriction_stream_client_frames_refused"
	// CounterStreamSnapshotFailed: a snapshot went out without its
	// restrictions because the store could not be read.
	CounterStreamSnapshotFailed = "restriction_stream_snapshot_failed"
	// CounterStreamResubscribeThrottled counts subscribe frames answered
	// by a deferred snapshot (at most one per StreamResubscribeEvery).
	CounterStreamResubscribeThrottled = "restriction_stream_resubscribe_throttled"
)

// Schemas of the console frames (M29).
const (
	schemaStatus    = "console/status/v1"
	schemaSnapshot  = "console/snapshot/v1"
	schemaSubscribe = "console/subscribe/v1"
)

// restrictionStream relays restriction/state/v1 to console clients: the
// versions this process commits (Local) and those any api replica puts
// on restr.v1 (the bus subscription), each once by (restriction,
// version).
type restrictionStream struct {
	svc      *restriction.Service
	policy   func(ctx context.Context) (policy.Policy, error)
	sessions *auth.SessionVerifier
	// degraded names what is degraded now (the bus, the CIS projection,
	// unpublished versions), for the status frame.
	degraded func() []string
	nats     func() string
	producer string

	// snapshotFailed and snapshotTruncated are what the last snapshot
	// could not hold, said in every status frame until one does.
	snapshotFailed, snapshotTruncated atomic.Bool

	mu      sync.Mutex
	clients map[*streamClient]struct{}
	seen    map[string]struct{}
	order   []string

	counters core.Counters
}

type streamClient struct {
	send    chan []byte
	dropped atomic.Int64
}

func newRestrictionStream(svc *restriction.Service, pol func(ctx context.Context) (policy.Policy, error), sessions *auth.SessionVerifier, producer string) *restrictionStream {
	return &restrictionStream{
		svc: svc, policy: pol, sessions: sessions, producer: producer,
		degraded: func() []string { return nil }, nats: func() string { return "" },
		clients: map[*streamClient]struct{}{}, seen: map[string]struct{}{},
	}
}

// Counters are the stream's counters.
func (st *restrictionStream) Counters() *core.Counters { return &st.counters }

// Offer relays one restriction/state/v1 message to every client, once
// per (restriction, version) whichever path brought it.
func (st *restrictionStream) Offer(key string, msg []byte) {
	st.mu.Lock()
	if _, dup := st.seen[key]; dup {
		st.mu.Unlock()
		st.counters.Inc(CounterStreamDuplicates)
		return
	}
	st.seen[key] = struct{}{}
	st.order = append(st.order, key)
	if len(st.order) > streamDedupe {
		delete(st.seen, st.order[0])
		st.order = st.order[1:]
	}
	clients := make([]*streamClient, 0, len(st.clients))
	for c := range st.clients {
		clients = append(clients, c)
	}
	st.mu.Unlock()
	for _, c := range clients {
		select {
		case c.send <- msg:
		default:
			c.dropped.Add(1)
			st.counters.Inc(CounterStreamDropped)
		}
	}
}

// OfferBus relays a message from restr.v1, keyed by its body.
func (st *restrictionStream) OfferBus(data []byte) {
	var m struct {
		Body struct {
			RestrictionID string `json:"restriction_id"`
			AnspVersion   int64  `json:"ansp_version"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &m); err != nil || m.Body.RestrictionID == "" {
		st.counters.Inc(CounterStreamClientFrame)
		return
	}
	st.Offer(m.Body.RestrictionID+"."+strconv.FormatInt(m.Body.AnspVersion, 10), data)
}

func (st *restrictionStream) add() (*streamClient, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.clients) >= MaxStreamClients {
		return nil, false
	}
	c := &streamClient{send: make(chan []byte, StreamSendBuffer)}
	st.clients[c] = struct{}{}
	return c, true
}

func (st *restrictionStream) remove(c *streamClient) {
	st.mu.Lock()
	delete(st.clients, c)
	st.mu.Unlock()
}

// sessionToken is the session the upgrade authenticated with (the
// bearer, or the uspace_session cookie), re-checked every status period
// so a session that ends mid-stream closes it with 4401.
func sessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if scheme, tok, ok := strings.Cut(h, " "); ok && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(tok)
		}
	}
	if c, err := r.Cookie(auth.CookieSession); err == nil {
		return c.Value
	}
	return ""
}

// StreamRestrictions serves GET /v1/restrictions/stream (WebSocket). The
// guard has judged the session and the Origin before this runs (M22).
func (s apiServer) StreamRestrictions(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil || s.rs.stream == nil {
		apierr.WriteError(w, r, apierr.Unavailable(restrictionsUnavailableRetry, "restrictions need the relational database (ANSP_RELATIONAL_DSN)"))
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		apierr.WriteError(w, r, apierr.UpgradeRequired())
		return
	}
	s.rs.stream.serve(w, r)
}

func (st *restrictionStream) serve(w http.ResponseWriter, r *http.Request) {
	c, ok := st.add()
	if !ok {
		st.counters.Inc(CounterStreamRefusedFull)
		apierr.WriteError(w, r, apierr.Unavailable(10*time.Second, "the restriction stream is at its connection limit"))
		return
	}
	defer st.remove(c)
	token := sessionToken(r)
	// The Origin allow-list of a cookie upgrade is the guard's (M22).
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(StreamReadLimit)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	connID := restriction.NewULID(time.Now())

	subscribe := make(chan struct{}, 1)
	go func() {
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f struct {
				Schema string `json:"schema"`
			}
			if json.Unmarshal(data, &f) != nil || f.Schema != schemaSubscribe {
				st.counters.Inc(CounterStreamClientFrame)
				continue
			}
			select {
			case subscribe <- struct{}{}:
			default:
			}
		}
	}()

	write := func(msg []byte) bool {
		wctx, wcancel := context.WithTimeout(ctx, streamWriteTimeout)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, msg) == nil
	}
	if !write(st.status(ctx, connID, c)) || !write(st.snapshot(ctx)) {
		return
	}
	gate := resubscribeGate{every: StreamResubscribeEvery, last: time.Now()}
	defer gate.stop()
	tick := time.NewTicker(StreamStatusPeriod)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.send:
			if !write(msg) {
				return
			}
		case <-subscribe:
			if !gate.ask(time.Now()) {
				st.counters.Inc(CounterStreamResubscribeThrottled)
				continue
			}
			if !write(st.snapshot(ctx)) {
				return
			}
		case <-gate.due():
			gate.served(time.Now())
			if !write(st.snapshot(ctx)) {
				return
			}
		case <-tick.C:
			if st.sessions != nil && token != "" {
				if _, err := st.sessions.Verify(ctx, token); errors.Is(err, auth.ErrSessionRefused) || isTokenError(err) {
					_ = conn.Close(auth.CloseReLogin, "the session has ended; sign in again")
					return
				}
			}
			if !write(st.status(ctx, connID, c)) {
				return
			}
		}
	}
}

// resubscribeGate answers a connection's console/subscribe/v1 frames
// with at most one snapshot per every: one inside the interval arms a
// single deferred snapshot at its end, and the frames in between are
// answered by it (ansp audit S-4).
type resubscribeGate struct {
	every time.Duration
	last  time.Time
	timer *time.Timer
}

// ask reports whether a snapshot may be sent at now (and records it);
// otherwise it arms the deferred snapshot, once.
func (g *resubscribeGate) ask(now time.Time) bool {
	if g.timer == nil && now.Sub(g.last) >= g.every {
		g.last = now
		return true
	}
	if g.timer == nil {
		g.timer = time.NewTimer(g.every - now.Sub(g.last))
	}
	return false
}

// due fires when the deferred snapshot is due (nil when none is armed).
func (g *resubscribeGate) due() <-chan time.Time {
	if g.timer == nil {
		return nil
	}
	return g.timer.C
}

// served records the deferred snapshot sent at now.
func (g *resubscribeGate) served(now time.Time) {
	g.timer, g.last = nil, now
}

func (g *resubscribeGate) stop() {
	if g.timer != nil {
		g.timer.Stop()
	}
}

// isTokenError reports whether err is core's refusal of the token
// itself (expired, signature, ...), not a failure to check it.
func isTokenError(err error) bool {
	var te *coreauth.TokenError
	return errors.As(err, &te)
}

// envelope is a console frame in the 04 section 2 envelope.
func (st *restrictionStream) envelope(schema string, body any) []byte {
	now := restriction.Stamp(time.Now())
	b, _ := json.Marshal(restriction.Envelope{
		Schema: schema, MsgID: restriction.NewULID(time.Now()), Producer: st.producer,
		Ts: now, RxTs: now, CapturedAt: now, TimeSource: restriction.TimeSourceSystem, Body: body,
	})
	return b
}

type statusBody struct {
	ConnectionID  string   `json:"connection_id"`
	ServerTs      string   `json:"server_ts"`
	PolicyVersion string   `json:"policy_version"`
	StaleAfterS   float64  `json:"stale_after_s"`
	LiveMaxAgeS   float64  `json:"live_max_age_s"`
	DroppedFrames int64    `json:"dropped_frames"`
	Degraded      []string `json:"degraded"`
	Sources       []any    `json:"sources"`
	CISVersion    *string  `json:"cis_version,omitempty"`
	CISAgeS       *float64 `json:"cis_age_s,omitempty"`
	NATS          string   `json:"nats,omitempty"`
}

// status is console/status/v1: the policy's thresholds (never defaulted
// by the console), what is degraded, the CIS projection's version and
// age, and the frames dropped for this connection.
func (st *restrictionStream) status(ctx context.Context, connID string, c *streamClient) []byte {
	degraded := append([]string{}, st.degraded()...)
	if st.snapshotFailed.Load() {
		degraded = append(degraded, "restriction_snapshot_unavailable")
	}
	if st.snapshotTruncated.Load() {
		degraded = append(degraded, "restriction_snapshot_truncated")
	}
	body := statusBody{ConnectionID: connID, ServerTs: restriction.Stamp(time.Now()), Sources: []any{}, DroppedFrames: c.dropped.Load(), NATS: st.nats()}
	if pol, err := st.policy(ctx); err == nil {
		body.PolicyVersion = strconv.FormatInt(pol.Version, 10)
		body.StaleAfterS, body.LiveMaxAgeS = pol.StaleAfterS, pol.StaleAfterS
	} else {
		degraded = append(degraded, "policy_unreadable")
		d := policy.Defaults()
		body.PolicyVersion, body.StaleAfterS, body.LiveMaxAgeS = "unknown", d.StaleAfterS, d.StaleAfterS
	}
	if snap, err := st.svc.Airspaces.Current(ctx); err == nil {
		v, age := snap.Version, max(0, time.Since(snap.FetchedAt).Seconds())
		body.CISVersion, body.CISAgeS = &v, &age
	} else {
		degraded = append(degraded, "cis_projection_unavailable")
	}
	body.Degraded = unique(degraded)
	return st.envelope(schemaStatus, body)
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

type snapshotBody struct {
	Tracks       []any             `json:"tracks"`
	Alerts       []any             `json:"alerts"`
	Manned       []any             `json:"manned"`
	ZonesVersion *string           `json:"zones_version"`
	Restrictions []json.RawMessage `json:"restrictions"`
}

// snapshot is console/snapshot/v1 with every planned and active
// restriction's current state message (this system's restrictions
// extra); tracks, alerts and manned are empty on this stream.
func (st *restrictionStream) snapshot(ctx context.Context) []byte {
	body := snapshotBody{Tracks: []any{}, Alerts: []any{}, Manned: []any{}, Restrictions: []json.RawMessage{}}
	if snap, err := st.svc.Airspaces.Current(ctx); err == nil {
		v := snap.Version
		body.ZonesVersion = &v
	}
	msgs, truncated, err := st.svc.Snapshot(ctx, StreamSnapshotLimit)
	if err != nil {
		st.counters.Inc(CounterStreamSnapshotFailed)
	}
	st.snapshotFailed.Store(err != nil)
	st.snapshotTruncated.Store(truncated)
	for _, m := range msgs {
		body.Restrictions = append(body.Restrictions, m)
	}
	return st.envelope(schemaSnapshot, body)
}
