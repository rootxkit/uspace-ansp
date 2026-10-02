//go:build integration

package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
)

// Row 21 over a real bucket: a session the api puts is live on the
// feed's checker; one it deletes is refused within the watch; one it
// never put is refused (absence).
func TestIntegrationLiveSessionsOverKV(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, Name: "sessions-test"}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	kv := b.KeyValue(bus.BucketSessionsLive)
	p := &auth.SessionProjector{KV: kv}
	c := &auth.KVSessionChecker{}
	fctx, stop := context.WithCancel(ctx)
	defer stop()
	go c.Follow(fctx, func(context.Context) (auth.WatchKV, error) { return kv, nil })
	live, gone := strings.Repeat("1", 32), strings.Repeat("2", 32)
	p.Started(ctx, live, auth.LiveSession{UserID: "u1", Role: auth.RoleViewer, ExpiresAt: time.Now().Add(time.Hour)})
	p.Started(ctx, gone, auth.LiveSession{UserID: "u2", Role: auth.RoleAdmin, ExpiresAt: time.Now().Add(time.Hour)})
	waitFor(t, func() bool { _, err := c.CheckSession(ctx, gone, "u2"); return err == nil })
	if role, err := c.CheckSession(ctx, live, "u1"); err != nil || role != auth.RoleViewer {
		t.Fatalf("live: %q %v", role, err)
	}
	p.Ended(ctx, gone)
	waitFor(t, func() bool { _, err := c.CheckSession(ctx, gone, "u2"); return errors.Is(err, auth.ErrSessionRefused) })
	if _, err := c.CheckSession(ctx, strings.Repeat("3", 32), "u3"); !errors.Is(err, auth.ErrSessionRefused) {
		t.Fatalf("absent: %v", err)
	}
	p.Ended(ctx, live)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
