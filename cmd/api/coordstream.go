package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Bounds of the coordination stream (E-10); the restriction stream's.
const (
	CoordStreamSnapshotLimit = 500
)

// Counters of the coordination stream.
const (
	CounterCoordStreamRefusedFull = "coordination_stream_refused_full"
	CounterCoordStreamDropped     = "coordination_stream_dropped_frames"
	CounterCoordStreamDuplicates  = "coordination_stream_duplicates"
	CounterCoordStreamClientFrame = "coordination_stream_client_frames_refused"
	CounterCoordStreamSnapshot    = "coordination_stream_snapshot_failed"
)

// coordStream relays coordination/notice/v1 to console clients: the
// changes this process commits (Local) and those any api replica puts
// on coord.v1, each once by (ack_id, event_seq).
type coordStream struct {
	svc      *coord.Service
	policy   func(ctx context.Context) (policy.Policy, error)
	sessions *auth.SessionVerifier
	degraded func() []string
	nats     func() string
	producer string

	snapshotFailed, snapshotTruncated atomic.Bool

	mu      sync.Mutex
	clients map[*streamClient]struct{}
	seen    map[string]struct{}
	order   []string

	counters core.Counters
}

func newCoordStream(svc *coord.Service, pol func(ctx context.Context) (policy.Policy, error), sessions *auth.SessionVerifier, producer string) *coordStream {
	return &coordStream{
		svc: svc, policy: pol, sessions: sessions, producer: producer,
		degraded: func() []string { return nil }, nats: func() string { return "" },
		clients: map[*streamClient]struct{}{}, seen: map[string]struct{}{},
	}
}

// Counters are the stream's counters.
func (st *coordStream) Counters() *core.Counters { return &st.counters }

// Offer relays one frame to every client, once per key whichever path
// brought it.
func (st *coordStream) Offer(key string, msg []byte) {
	st.mu.Lock()
	if _, dup := st.seen[key]; dup {
		st.mu.Unlock()
		st.counters.Inc(CounterCoordStreamDuplicates)
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
			st.counters.Inc(CounterCoordStreamDropped)
		}
	}
}

// OfferBus relays a coord.v1 message keyed by its JetStream message id
// (<ack_id>.<event_seq>), or by its bytes when it has none.
func (st *coordStream) OfferBus(msgID string, data []byte) {
	if !json.Valid(data) {
		st.counters.Inc(CounterCoordStreamClientFrame)
		return
	}
	if msgID == "" {
		sum := sha256.Sum256(data)
		msgID = "sha256:" + hex.EncodeToString(sum[:])
	}
	st.Offer(msgID, data)
}

func (st *coordStream) add() (*streamClient, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.clients) >= MaxStreamClients {
		return nil, false
	}
	c := &streamClient{send: make(chan []byte, StreamSendBuffer)}
	st.clients[c] = struct{}{}
	return c, true
}

func (st *coordStream) remove(c *streamClient) {
	st.mu.Lock()
	delete(st.clients, c)
	st.mu.Unlock()
}

func (st *coordStream) serve(w http.ResponseWriter, r *http.Request) {
	c, ok := st.add()
	if !ok {
		st.counters.Inc(CounterCoordStreamRefusedFull)
		apierr.WriteError(w, r, apierr.Unavailable(10*time.Second, "the coordination stream is at its connection limit"))
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
				st.counters.Inc(CounterCoordStreamClientFrame)
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

func (st *coordStream) envelope(schema string, body any) []byte {
	now := restriction.Stamp(time.Now())
	b, _ := json.Marshal(restriction.Envelope{
		Schema: schema, MsgID: restriction.NewULID(time.Now()), Producer: st.producer,
		Ts: now, RxTs: now, CapturedAt: now, TimeSource: restriction.TimeSourceSystem, Body: body,
	})
	return b
}

// status is console/status/v1: the policy's thresholds, what is
// degraded (the bus, changes not yet on coord.v1, a snapshot that could
// not be read) and the frames dropped for this connection.
func (st *coordStream) status(ctx context.Context, connID string, c *streamClient) []byte {
	degraded := append([]string{}, st.degraded()...)
	if st.snapshotFailed.Load() {
		degraded = append(degraded, "coordination_snapshot_unavailable")
	}
	if st.snapshotTruncated.Load() {
		degraded = append(degraded, "coordination_snapshot_truncated")
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
	body.Degraded = unique(degraded)
	return st.envelope(schemaStatus, body)
}

type coordSnapshotBody struct {
	Tracks       []any             `json:"tracks"`
	Alerts       []any             `json:"alerts"`
	Manned       []any             `json:"manned"`
	ZonesVersion *string           `json:"zones_version"`
	Notices      []json.RawMessage `json:"notices"`
}

// snapshot is console/snapshot/v1 with every notice not acknowledged
// (this system's notices extra).
func (st *coordStream) snapshot(ctx context.Context) []byte {
	body := coordSnapshotBody{Tracks: []any{}, Alerts: []any{}, Manned: []any{}, Notices: []json.RawMessage{}}
	frames, truncated, err := st.svc.Snapshot(ctx, CoordStreamSnapshotLimit)
	if err != nil {
		st.counters.Inc(CounterCoordStreamSnapshot)
	}
	st.snapshotFailed.Store(err != nil)
	st.snapshotTruncated.Store(truncated)
	body.Notices = append(body.Notices, frames...)
	return st.envelope(schemaSnapshot, body)
}
