//go:build integration

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
)

// The console's live picture stream against real NATS, with manned-feed
// started as deploy/compose.prod.yaml starts it (row 54): the public
// part of the session key in ANSP_SESSION_PUBLIC_KEY_FILE, no signing
// key. A session api projects to sessions_live streams (101); once api
// ends it (the key deleted) it is refused 401. Started without the
// public key, the same live session is refused 401 and the log says why.
func TestIntegrationConsoleSessionStream(t *testing.T) {
	ring, pub := sessionKey(t)
	p := startFeed(t, "ANSP_SESSION_PUBLIC_KEY_FILE="+pub, "ANSP_PUBLIC_BASE_URL="+origin, "ANSP_WS_ALLOWED_ORIGINS="+origin)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	projector := &auth.SessionProjector{KV: p.b.KeyValue(bus.BucketSessionsLive)}
	jti := strings.Repeat("7", 32)
	now := time.Now().UTC().Truncate(time.Second)
	projector.Started(ctx, jti, auth.LiveSession{UserID: "user-7", Role: auth.RoleViewer, ExpiresAt: now.Add(time.Hour)})
	t.Cleanup(func() { projector.Ended(context.Background(), jti) })
	tok := issue(t, ring, jti, auth.RealmConsole, now, now.Add(time.Hour))

	stream := func(tok string) int {
		h := cookieUpgrade(tok)
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		code, _ := dialAddr(dctx, p.addr, h)
		return code
	}
	waitCode := func(what string, want int, tok string) {
		t.Helper()
		deadline := time.Now().Add(auth.DefaultSessionCacheTTL + 15*time.Second)
		for {
			got := stream(tok)
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d, want %d; log:\n%s", what, got, want, p.out.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitCode("a live session", http.StatusSwitchingProtocols, tok)
	projector.Ended(ctx, jti)
	waitCode("an ended session", http.StatusUnauthorized, tok)

	// Absence of the key: the same session, live again, is refused.
	projector.Started(ctx, jti, auth.LiveSession{UserID: "user-7", Role: auth.RoleViewer, ExpiresAt: now.Add(time.Hour)})
	q := startFeed(t, "ANSP_PUBLIC_BASE_URL="+origin, "ANSP_WS_ALLOWED_ORIGINS="+origin)
	h := cookieUpgrade(tok)
	if code, _ := dialAddr(ctx, q.addr, h); code != http.StatusUnauthorized {
		t.Fatalf("without the public key: %d, want 401", code)
	}
	if log := q.out.String(); !strings.Contains(log, "console sessions are refused (401): ANSP_SESSION_PUBLIC_KEY_FILE is not set") {
		t.Fatalf("the log does not say why sessions are refused:\n%s", log)
	}
}

// dialAddr upgrades GET /v1/manned-traffic/stream on addr with h and
// returns the answer's status.
func dialAddr(ctx context.Context, addr string, h http.Header) (int, error) {
	c, resp, err := websocket.Dial(ctx, "ws://"+addr+"/v1/manned-traffic/stream", &websocket.DialOptions{HTTPHeader: h})
	if err == nil {
		defer c.CloseNow()
		return resp.StatusCode, nil
	}
	if resp != nil {
		return resp.StatusCode, err
	}
	return 0, err
}
