package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// sessionSeenEvery is how often an open console stream reports its
// session as in use (the api's touchEvery; docs/PLAN.md section 15 row
// 21 (4)).
const sessionSeenEvery = time.Minute

// viewer is who asks: the client id the caps and feed_products count
// by, whether it sees every aircraft (a console session) and the
// session token to re-check.
type viewer struct {
	clientID string
	all      bool
	session  bool
	jti      string
	token    string
}

func viewerOf(r *http.Request) (viewer, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.Claims.Subject == "" {
		return viewer{}, false
	}
	if p.Session {
		return viewer{clientID: "console:" + p.Claims.Subject, all: true, session: true, jti: p.Claims.JTI, token: sessionToken(r)}, true
	}
	return viewer{clientID: p.Claims.Subject}, true
}

// sessionToken is the session the request authenticated with: the
// bearer, or the uspace_session cookie of a same-origin upgrade (M22).
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

func badBBox(err error) *apierr.Problem {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return apierr.Invalid(fe)
	}
	return apierr.Invalid(core.Fieldf("bbox", "invalid"))
}

// ServeSnapshot answers GET /v1/manned-traffic/snapshot: every aircraft
// the caller is served (relevant ones for a machine client, every one
// flagged for the console) with its age, what is degraded and why, the
// adapters, the CIS version and age, the policy_version. An empty
// picture says manned: [] with degraded saying why, never merely [].
func (s *Service) ServeSnapshot(w http.ResponseWriter, r *http.Request) {
	v, ok := viewerOf(r)
	if !ok {
		apierr.WriteError(w, r, apierr.Unauthenticated("no authenticated caller"))
		return
	}
	bbox, err := ParseBBox(r.URL.Query().Get("bbox"))
	if err != nil {
		apierr.WriteError(w, r, badBBox(err))
		return
	}
	b, err := json.Marshal(s.Snapshot(bbox, v.all))
	if err != nil {
		apierr.WriteInternal(w, r, fmt.Errorf("encode the snapshot: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// ServeStream serves GET /v1/manned-traffic/stream (WebSocket). The
// guard has judged the token or the session cookie and its Origin before
// this runs (M22); the caps are judged here, before the upgrade.
func (s *Service) ServeStream(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		apierr.WriteError(w, r, apierr.UpgradeRequired())
		return
	}
	v, ok := viewerOf(r)
	if !ok {
		apierr.WriteError(w, r, apierr.Unauthenticated("no authenticated caller"))
		return
	}
	bbox, err := ParseBBox(r.URL.Query().Get("bbox"))
	if err != nil {
		apierr.WriteError(w, r, badBBox(err))
		return
	}
	now := s.d.Clock()
	c := &client{id: manned.NewULID(now), clientID: v.clientID, all: v.all, bbox: bbox, manned: true,
		max: s.cfg.SendQueue, notify: make(chan struct{}, 1)}
	if ok, perClient := s.add(c); !ok {
		name, detail := CounterRefusedTotal, "the manned traffic stream is at its connection limit"
		if perClient {
			name, detail = CounterRefusedPerClient, "this client is at its connection limit"
		}
		s.counters.Inc(name)
		apierr.WriteError(w, r, apierr.Unavailable(s.cfg.RetryAfter, detail))
		return
	}
	defer s.remove(c)
	// The Origin allow-list of a cookie upgrade is the guard's (M22); a
	// machine client sends no Origin.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(MaxClientFrameBytes)
	s.serve(r.Context(), conn, c, v)
}

func (s *Service) serve(parent context.Context, conn *websocket.Conn, c *client, v viewer) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	resubscribe := make(chan struct{}, 1)
	go func() {
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			sub, err := DecodeSubscribe(data)
			if err != nil {
				s.counters.Inc(CounterClientFrameBad)
				continue
			}
			c.subscribe(sub)
			select {
			case resubscribe <- struct{}{}:
			default:
			}
		}
	}()
	write := func(msg any) bool {
		b, ok := msg.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(msg); err != nil {
				return false
			}
		}
		wctx, wcancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
		defer wcancel()
		if err := conn.Write(wctx, websocket.MessageText, b); err != nil {
			if errors.Is(wctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				s.counters.Inc(CounterSlowClosed)
				_ = conn.Close(websocket.StatusTryAgainLater, "the client does not keep up")
			}
			return false
		}
		s.counters.Inc(CounterFramesSent)
		return true
	}
	snapshot := func() bool {
		now := s.d.Clock()
		c.mu.Lock()
		bbox, manned := c.bbox, c.manned
		c.mu.Unlock()
		body := s.snapshotBody(bbox, c.all, now)
		if !manned {
			body.Manned = body.Manned[:0]
		}
		return write(systemEnvelope(SchemaSnapshot, now, body))
	}
	if !write(s.status(c, s.d.Clock())) || !snapshot() {
		return
	}
	if v.session {
		s.seen(v.jti)
	}
	lastSeen := s.d.Clock()
	status := time.NewTicker(s.cfg.StatusPeriod)
	defer status.Stop()
	products := time.NewTicker(s.cfg.ProductPeriod)
	defer products.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.notify:
			for _, f := range c.take() {
				if !write(f.frame) {
					return
				}
				c.written(f)
			}
		case <-resubscribe:
			if !snapshot() {
				return
			}
		case <-status.C:
			now := s.d.Clock()
			if v.session {
				if !s.sessionLive(ctx, v.token) {
					s.counters.Inc(CounterSessionClosed)
					_ = conn.Close(auth.CloseReLogin, "the session has ended or cannot be checked; sign in again")
					return
				}
				if now.Sub(lastSeen) >= sessionSeenEvery {
					s.seen(v.jti)
					lastSeen = now
				}
			}
			if !write(s.status(c, now)) {
				return
			}
		case <-products.C:
			s.product(c)
		}
	}
}

// sessionLive re-checks a console session: refused, expired and
// unanswerable (the live-session projection unreachable) all close the
// stream with 4401 (docs/PLAN.md section 15 row 21 (2)).
func (s *Service) sessionLive(ctx context.Context, token string) bool {
	if s.d.Sessions == nil || token == "" {
		return false
	}
	_, err := s.d.Sessions.Verify(ctx, token)
	return err == nil
}

func (s *Service) seen(jti string) {
	if s.d.SessionSeen != nil && jti != "" {
		s.d.SessionSeen(jti)
	}
}

func (s *Service) product(c *client) {
	sent, relevant := c.takeProduct()
	if s.d.Products == nil {
		return
	}
	s.d.Products.Record(Product{ClientID: c.clientID, TracksSent: sent, TracksRelevant: relevant,
		Degraded: s.Degraded(s.d.Clock()), PolicyVersion: s.policy().Version})
}
