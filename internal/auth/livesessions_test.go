package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go/jetstream"
	coreauth "github.com/rootxkit/uspace-core/auth"
)

var lt0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func jti(c byte) string { return strings.Repeat(string(c), 32) }

type liveEntry struct {
	key   string
	value []byte
	op    jetstream.KeyValueOp
}

func (e *liveEntry) Bucket() string                  { return "sessions_live" }
func (e *liveEntry) Key() string                     { return e.key }
func (e *liveEntry) Value() []byte                   { return e.value }
func (e *liveEntry) Revision() uint64                { return 1 }
func (e *liveEntry) Created() time.Time              { return time.Time{} }
func (e *liveEntry) Delta() uint64                   { return 0 }
func (e *liveEntry) Operation() jetstream.KeyValueOp { return e.op }

type keyChan struct{ ch chan string }

func (k keyChan) Keys() <-chan string { return k.ch }
func (k keyChan) Stop() error         { return nil }

// memKV is sessions_live in memory, with switches to fail.
type memKV struct {
	mu      sync.Mutex
	vals    map[string][]byte
	putErr  error
	delErr  error
	listErr error
	watch   chan *liveWatcher
}

type liveWatcher struct {
	ch      chan jetstream.KeyValueEntry
	stopped chan struct{}
	once    sync.Once
}

func (w *liveWatcher) Updates() <-chan jetstream.KeyValueEntry { return w.ch }
func (w *liveWatcher) Stop() error                             { w.once.Do(func() { close(w.stopped) }); return nil }

func newMemKV() *memKV { return &memKV{vals: map[string][]byte{}, watch: make(chan *liveWatcher, 8)} }

func (k *memKV) Put(_ context.Context, key string, value []byte) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.putErr != nil {
		return 0, k.putErr
	}
	k.vals[key] = value
	return 1, nil
}

func (k *memKV) Delete(_ context.Context, key string, _ ...jetstream.KVDeleteOpt) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.delErr != nil {
		return k.delErr
	}
	if _, ok := k.vals[key]; !ok {
		return jetstream.ErrKeyNotFound
	}
	delete(k.vals, key)
	return nil
}

func (k *memKV) ListKeys(context.Context, ...jetstream.WatchOpt) (jetstream.KeyLister, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.listErr != nil {
		return nil, k.listErr
	}
	if len(k.vals) == 0 {
		return nil, jetstream.ErrNoKeysFound
	}
	ch := make(chan string, len(k.vals))
	for key := range k.vals {
		ch <- key
	}
	close(ch)
	return keyChan{ch: ch}, nil
}

// WatchAll sends the current values, the end-of-initial marker, and
// then whatever the test pushes on the returned watcher.
func (k *memKV) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.listErr != nil {
		return nil, k.listErr
	}
	w := &liveWatcher{ch: make(chan jetstream.KeyValueEntry, 64), stopped: make(chan struct{})}
	for key, v := range k.vals {
		w.ch <- &liveEntry{key: key, value: v, op: jetstream.KeyValuePut}
	}
	w.ch <- nil
	k.watch <- w
	return w, nil
}

func (k *memKV) has(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.vals[key]
	return ok
}

type lister struct {
	rows []SessionRow
	err  error
}

func (l *lister) LiveSessions(context.Context, time.Duration, int) ([]SessionRow, error) {
	return l.rows, l.err
}

func liveJSON(t *testing.T, user, role string, exp time.Time) []byte {
	b, err := json.Marshal(LiveSession{UserID: user, Role: role, ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProjectorWritesThroughAndResyncs(t *testing.T) {
	kv := newMemKV()
	l := &lister{rows: []SessionRow{{JTI: jti('a'), UserID: "u1", Role: RoleViewer, ExpiresAt: lt0.Add(time.Hour)}}}
	p := &SessionProjector{KV: kv, Lister: l, Idle: SessionIdleTimeout}
	ctx := context.Background()
	p.Started(ctx, jti('b'), LiveSession{UserID: "u2", Role: RoleAdmin, ExpiresAt: lt0.Add(time.Hour)})
	p.Started(ctx, "not-a-jti", LiveSession{})
	if !kv.has(jti('b')) || p.Counters().Get(CounterLivePut) != 1 || p.Counters().Get(CounterLivePutFailed) != 1 {
		t.Fatalf("started: %v", p.Counters().Snapshot())
	}
	// A stale key the database does not hold (a lost delete) and the
	// live one it does: the resync deletes the first and puts the second.
	kv.vals[jti('c')] = liveJSON(t, "u3", RoleViewer, lt0.Add(time.Hour))
	put, deleted, err := p.Resync(ctx)
	if err != nil || put != 1 || deleted != 2 || !kv.has(jti('a')) || kv.has(jti('b')) || kv.has(jti('c')) {
		t.Fatalf("resync put %d deleted %d %v; keys %v", put, deleted, err, kv.vals)
	}
	p.Ended(ctx, jti('a'), jti('9'), "bad")
	if kv.has(jti('a')) || p.Counters().Get(CounterLiveDeleted) != 2 || p.Counters().Get(CounterLiveDeleteFailed) != 1 {
		t.Fatalf("ended: %v", p.Counters().Snapshot())
	}
	// Failures are counted, never retried inline.
	kv.putErr, kv.delErr = errors.New("down"), errors.New("down")
	p.Started(ctx, jti('d'), LiveSession{UserID: "u", Role: RoleViewer, ExpiresAt: lt0})
	p.Ended(ctx, jti('a'))
	kv.vals[jti('e')] = []byte(`{}`)
	if _, _, err := p.Resync(ctx); err == nil {
		t.Fatal("resync with a failing put said nothing")
	}
	kv.putErr = nil
	if _, _, err := p.Resync(ctx); err == nil {
		t.Fatal("resync with a failing delete said nothing")
	}
	kv.delErr, kv.listErr = nil, errors.New("down")
	if _, _, err := p.Resync(ctx); err == nil {
		t.Fatal("resync with a failing list said nothing")
	}
	kv.listErr = nil
	l.err = errors.New("db down")
	if _, _, err := p.Resync(ctx); err == nil || p.Counters().Get(CounterLiveResyncFailed) < 4 {
		t.Fatalf("a failing listing: %v", p.Counters().Snapshot())
	}
	var none SessionProjector
	if _, _, err := none.Resync(ctx); !errors.Is(err, ErrLiveSessionsUnavailable) {
		t.Fatal(err)
	}
	none.Ended(ctx, jti('a'))
	none.Started(ctx, jti('a'), LiveSession{})
}

// TestAResyncCutAtTheBoundDeletesNothing: a listing past MaxLiveSessions
// never ends a live session that was not listed.
func TestAResyncCutAtTheBoundDeletesNothing(t *testing.T) {
	kv := newMemKV()
	rows := make([]SessionRow, MaxLiveSessions+1)
	for i := range rows {
		rows[i] = SessionRow{JTI: jti('a'), UserID: "u", Role: RoleViewer, ExpiresAt: lt0}
	}
	kv.vals[jti('f')] = liveJSON(t, "u", RoleViewer, lt0)
	p := &SessionProjector{KV: kv, Lister: &lister{rows: rows}}
	if _, deleted, err := p.Resync(context.Background()); err != nil || deleted != 0 || !kv.has(jti('f')) || p.Counters().Get(CounterLiveResyncCut) != 1 {
		t.Fatalf("deleted %d %v", deleted, err)
	}
}

func TestProjectorRunResyncsUntilCancelled(t *testing.T) {
	kv := newMemKV()
	p := &SessionProjector{KV: kv, Lister: &lister{err: errors.New("down")}}
	ctx, cancel := context.WithCancel(context.Background())
	var got error
	done := make(chan struct{})
	go func() {
		p.Run(ctx, time.Hour, func(err error) { got = err; cancel() })
		close(done)
	}()
	<-done
	if got == nil {
		t.Fatal("no error reported")
	}
}

func TestDecodeLiveSession(t *testing.T) {
	if _, err := DecodeLiveSession(liveJSON(t, "u", RoleViewer, lt0)); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{`{}`, `{"user_id":"u","role":"viewer","expires_at":"2026-10-02T12:00:00Z","x":1}`, `[`, strings.Repeat("x", 2000)} {
		if _, err := DecodeLiveSession([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

type checkerRig struct {
	kv    *memKV
	c     *KVSessionChecker
	now   time.Time
	mu    sync.Mutex
	up    bool
	stop  context.CancelFunc
	done  chan struct{}
	watch *liveWatcher
}

func (r *checkerRig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *checkerRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func newCheckerRig(t *testing.T) *checkerRig {
	r := &checkerRig{kv: newMemKV(), now: lt0, up: true}
	r.kv.vals[jti('a')] = liveJSON(t, "u1", RoleViewer, lt0.Add(time.Hour))
	r.c = &KVSessionChecker{Resync: time.Hour, Now: r.clock, Up: func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.up }}
	ctx, cancel := context.WithCancel(context.Background())
	r.stop, r.done = cancel, make(chan struct{})
	go func() {
		r.c.Follow(ctx, func(context.Context) (WatchKV, error) { return r.kv, nil })
		close(r.done)
	}()
	r.watch = <-r.kv.watch
	t.Cleanup(func() { cancel(); <-r.done })
	deadline := time.Now().Add(2 * time.Second)
	for {
		if ok, _ := r.c.Healthy(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never synced")
		}
		time.Sleep(time.Millisecond)
	}
	return r
}

// TestCheckerAbsenceRefusesPresenceAdmits is row 21 (1) and its twin.
func TestCheckerAbsenceRefusesPresenceAdmits(t *testing.T) {
	r := newCheckerRig(t)
	ctx := context.Background()
	if role, err := r.c.CheckSession(ctx, jti('a'), "u1"); err != nil || role != RoleViewer {
		t.Fatalf("live: %q %v", role, err)
	}
	if _, err := r.c.CheckSession(ctx, jti('b'), "u1"); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("absent: %v", err)
	}
	if _, err := r.c.CheckSession(ctx, jti('a'), "u2"); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("another account: %v", err)
	}
	// A delete on the watch ends it at once; a put adds one.
	r.watch.ch <- &liveEntry{key: jti('a'), op: jetstream.KeyValueDelete}
	r.watch.ch <- &liveEntry{key: jti('c'), value: liveJSON(t, "u3", RoleAdmin, lt0.Add(time.Minute)), op: jetstream.KeyValuePut}
	r.watch.ch <- &liveEntry{key: jti('d'), value: []byte(`{}`), op: jetstream.KeyValuePut}
	deadline := time.Now().Add(2 * time.Second)
	for r.c.Counters().Get(CounterLiveUndecodable) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("len %d", r.c.Len())
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := r.c.CheckSession(ctx, jti('a'), "u1"); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("deleted: %v", err)
	}
	if role, err := r.c.CheckSession(ctx, jti('c'), "u3"); err != nil || role != RoleAdmin {
		t.Fatalf("put: %v", err)
	}
	// Past its expires_at without a delete: refused.
	r.advance(2 * time.Minute)
	if _, err := r.c.CheckSession(ctx, jti('c'), "u3"); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("expired: %v", err)
	}
	if r.c.Counters().Get(CounterLiveUndecodable) != 1 {
		t.Fatal("undecodable not counted")
	}
}

// TestCheckerOutageRefusesAfterOneResync is row 21 (2): the bus down
// for longer than one resync period makes every check unanswerable
// (not a refusal of the session); back up, it answers again.
func TestCheckerOutageRefusesAfterOneResync(t *testing.T) {
	r := newCheckerRig(t)
	r.mu.Lock()
	r.up = false
	r.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for {
		r.c.mu.RLock()
		lost := !r.c.lostSince.IsZero()
		r.c.mu.RUnlock()
		if lost {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the outage was not noticed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Within one period: still answered from what was read.
	if _, err := r.c.CheckSession(context.Background(), jti('a'), "u1"); err != nil {
		t.Fatalf("within one period: %v", err)
	}
	r.advance(time.Hour + time.Second)
	_, err := r.c.CheckSession(context.Background(), jti('a'), "u1")
	if !errors.Is(err, ErrLiveSessionsUnavailable) || errors.Is(err, ErrSessionRefused) {
		t.Fatalf("after one period: %v", err)
	}
	if ok, why := r.c.Healthy(); ok || !strings.Contains(why, "unreachable since") {
		t.Fatalf("healthy %v %q", ok, why)
	}
	r.mu.Lock()
	r.up = true
	r.mu.Unlock()
	deadline = time.Now().Add(5 * time.Second)
	for {
		if ok, _ := r.c.Healthy(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never recovered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if r.c.Counters().Get(CounterLiveUnanswerable) != 1 {
		t.Fatal("not counted")
	}
}

func TestCheckerNeverReadRefuses(t *testing.T) {
	c := &KVSessionChecker{}
	if _, err := c.CheckSession(context.Background(), jti('a'), "u"); !errors.Is(err, ErrLiveSessionsUnavailable) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan struct{})
	go func() {
		c.Follow(ctx, func(context.Context) (WatchKV, error) {
			calls++
			cancel()
			return nil, errors.New("no bucket")
		})
		close(done)
	}()
	<-done
	if calls != 1 {
		t.Fatal(calls)
	}
}

type touchStore struct {
	Store
	touched []string
	err     error
}

func (s *touchStore) TouchSession(_ context.Context, jti string) error {
	s.touched = append(s.touched, jti)
	return s.err
}

func TestSessionSeenTouchesOnlyWellFormedSessions(t *testing.T) {
	st := &touchStore{}
	a := &Accounts{store: st}
	if err := a.SessionSeen(context.Background(), jti('a')); err != nil || len(st.touched) != 1 {
		t.Fatal(err)
	}
	if err := a.SessionSeen(context.Background(), "x' OR 1=1"); err == nil || len(st.touched) != 1 || a.Counters().Get(CounterLiveSeenRefused) != 1 {
		t.Fatal("a malformed id was touched")
	}
	st.err = errors.New("down")
	if err := a.SessionSeen(context.Background(), jti('b')); err == nil {
		t.Fatal("a store failure was hidden")
	}
}

type projectionSpy struct {
	mu      sync.Mutex
	started []string
	ended   []string
}

func (p *projectionSpy) Started(_ context.Context, jti string, _ LiveSession) {
	p.mu.Lock()
	p.started = append(p.started, jti)
	p.mu.Unlock()
}

func (p *projectionSpy) Ended(_ context.Context, jtis ...string) {
	p.mu.Lock()
	p.ended = append(p.ended, jtis...)
	p.mu.Unlock()
}

func TestEndedTellsTheProjection(t *testing.T) {
	spy := &projectionSpy{}
	a := &Accounts{}
	a.ended(context.Background(), jti('a'))
	a.SetProjection(spy)
	a.ended(context.Background())
	a.ended(context.Background(), jti('a'), jti('b'))
	if len(spy.ended) != 2 {
		t.Fatalf("ended %v", spy.ended)
	}
}

// TestUncheckedCookieUpgradeClosesWith4401: with UpgradeReLogin, a
// session that cannot be checked is answered on the WebSocket with the
// close the console reads; without it, 503 (the twin).
func TestUncheckedCookieUpgradeClosesWith4401(t *testing.T) {
	for _, relogin := range []bool{true, false} {
		g := &Guard{Origins: []string{"https://ansp.test"}, UpgradeReLogin: relogin}
		h := g.RequireUpgrade(Access{AnyRole: true})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("the handler ran")
		}))
		sv, tok := unanswerableSessions(t)
		g.Sessions = sv
		srv := httptest.NewServer(h)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		hdr := http.Header{}
		hdr.Set("Origin", "https://ansp.test")
		hdr.Set("Cookie", CookieSession+"="+tok)
		conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{HTTPHeader: hdr})
		if relogin {
			if err != nil {
				t.Fatalf("relogin: %v", err)
			}
			_, _, rerr := conn.Read(ctx)
			if websocket.CloseStatus(rerr) != CloseReLogin {
				t.Fatalf("closed with %v", rerr)
			}
		} else if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("without relogin: %v", err)
		}
		cancel()
		srv.Close()
	}
}

// unanswerableSessions is a session verifier whose checker has never
// read sessions_live (every check unanswerable) and a valid session
// token for it.
func unanswerableSessions(t *testing.T) (*SessionVerifier, string) {
	t.Helper()
	ring := sessionRing(t)
	sv, err := NewSessionVerifier(context.Background(), SessionVerifierConfig{Issuer: ownIssuer, Ring: ring, Audiences: audiences(),
		Checker: &KVSessionChecker{}})
	must(t, err)
	iss, err := ring.Issuer(ownIssuer)
	must(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	tok, err := iss.IssueSession(coreauth.SessionClaims{Audience: ownHost, Subject: "u1", Roles: []string{RoleViewer}, Realm: RealmConsole,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: jti('a')})
	must(t, err)
	return sv, tok
}
