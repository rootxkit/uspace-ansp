//go:build integration

package policy_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// policyKV is the real KV bucket policy on the integration NATS,
// emptied first so the follower starts with nothing.
func policyKV(t *testing.T) (*bus.Bus, jetstream.KeyValue) {
	t.Helper()
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, CredsFile: os.Getenv("ANSP_NATS_CREDS"), Name: "policy-integration"},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	kv, err := b.JetStream().KeyValue(ctx, bus.BucketPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.Purge(ctx, policy.KVKey); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatal(err)
	}
	return b, kv
}

// failingKV is a KV that cannot take a put.
type failingKV struct{}

func (failingKV) Put(context.Context, string, []byte) (uint64, error) {
	return 0, errors.New("nats: no responders available for request")
}

// The whole path against real PostgreSQL and NATS: a follower with an
// empty bucket serves the defaults and says so; Update stores version 2,
// writes its audit event and puts it into KV in the same transaction;
// the follower watching KV applies it. With KV unable to take the put
// the update is refused (503) and neither the row nor the event exists
// (E-01 pair).
func TestIntegrationUpdateReachesTheFollower(t *testing.T) {
	b, kv := policyKV(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	svc := &policy.Service{Repo: store.PolicyRepo{DB: db}, KV: kv, Notify: b.Conn()}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := policy.NewFollower(nil)
	runDone := make(chan error, 1)
	go func() { runDone <- f.Run(ctx, kv) }()
	if f.Status() != "policy: defaults, KV empty" {
		t.Fatalf("before any update: %s", f.Status())
	}

	refused := &policy.Service{Repo: store.PolicyRepo{DB: db}, KV: failingKV{}}
	p := policy.Policy{Thresholds: policy.Defaults()}
	p.FeedMarginLateralM = 8000
	if _, err := refused.Update(ctx, policy.Actor{Type: "user", ID: "admin-1"}, p); !errors.Is(err, policy.ErrKVUnavailable) {
		t.Fatalf("KV down: %v", err)
	}
	if latest, err := svc.Load(ctx); err != nil || latest.Version != 1 {
		t.Fatalf("after the refusal the latest is %+v %v", latest, err)
	}
	if n := count(t, db, `SELECT count(*) FROM events WHERE event_type = 'policy_updated'`); n != 0 {
		t.Fatalf("a refused update left %d events", n)
	}

	v, err := svc.Update(ctx, policy.Actor{Type: "user", ID: "admin-1"}, p)
	if err != nil {
		t.Fatal(err)
	}
	// The refused attempt consumed a sequence value: versions only go
	// forward, gaps are allowed.
	if v < 2 {
		t.Fatalf("version %d", v)
	}
	if n := count(t, db, `SELECT count(*) FROM events WHERE event_type = 'policy_updated'`); n != 1 {
		t.Fatalf("%d events", n)
	}
	deadline := time.Now().Add(10 * time.Second)
	for f.Version() != v {
		if time.Now().After(deadline) {
			t.Fatalf("follower still at %s, want version %d", f.Status(), v)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cur, fromKV := f.Current(); !fromKV || cur.FeedMarginLateralM != 8000 || cur.ChangedBy != "admin-1" {
		t.Fatalf("follower holds %+v", cur)
	}

	// A follower started later reads the value already in KV; Republish
	// writes the same version again, which it ignores silently.
	late := policy.NewFollower(nil)
	go func() { _ = late.Run(ctx, kv) }()
	if _, err := svc.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	for late.Version() != v {
		if time.Now().After(deadline) {
			t.Fatalf("late follower: %s", late.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if late.Counters().Get(policy.CounterOlderIgnored) != 0 {
		t.Fatal("an equal version counted as older")
	}
	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}

func count(t *testing.T, db *store.Relational, sql string) int64 {
	t.Helper()
	var n int64
	err := db.Do(context.Background(), func(ctx context.Context, c relational.DBTX, _ *relational.Queries) error {
		return c.QueryRow(ctx, sql).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
