//go:build integration

package sources_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/sources"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// SC-08 steps 1-2 over the real stores: an admin's switch is committed,
// put to KV and pushed; a follower on the push and one reading KV both
// say disabled with who and why. The twin: with the bucket unreachable
// nothing is written to the database.
func TestIntegrationSwitchReachesTheFollowers(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db := storetest.Relational(t, storetest.Scratch(t, store.TreeRelational, true), store.RoleRelational)
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, Name: "sources-test"}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	repo := store.SourcesRepo{DB: db}
	pushed := sources.NewFollower(nil)
	sub, err := b.Conn().Subscribe(sources.SubjectControl, func(m *nats.Msg) { pushed.ApplyJSON(m.Data) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// The twin first: a bucket that does not answer refuses the change
	// before the database is touched.
	broken := &sources.Writer{Repo: repo, KV: b.KeyValue("no_such_bucket"), Push: b.Conn()}
	inst := "replay-sc08"
	if _, _, _, err := broken.Set(ctx, sources.Change{SourceType: "manned", InstanceID: &inst, Enabled: false, Reason: "r", Actor: "admin-1"}); !errors.Is(err, sources.ErrKVUnavailable) {
		t.Fatalf("broken bucket: %v", err)
	}
	if doc, _ := repo.Load(ctx); len(doc.Controls) != 0 {
		t.Fatalf("a row was written without KV: %+v", doc)
	}

	w := &sources.Writer{Repo: repo, KV: b.KeyValue(bus.BucketSourceControl), Push: b.Conn()}
	row, doc, putErr, err := w.Set(ctx, sources.Change{SourceType: "manned", InstanceID: &inst, Enabled: false, Reason: "SC-08 maintenance", Actor: "admin-1"})
	if err != nil || putErr != nil || row.Enabled {
		t.Fatalf("set: %v %v", err, putErr)
	}
	read := sources.NewFollower(nil)
	if err := read.Read(ctx, b.KeyValue(bus.BucketSourceControl)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, _, _ := pushed.Version()
		if v == doc.Version {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the push never arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for name, f := range map[string]*sources.Follower{"push": pushed, "kv": read} {
		d := f.Decision("manned", &inst)
		if d.Enabled || d.Actor != "admin-1" || d.Reason != "SC-08 maintenance" {
			t.Fatalf("%s: %+v", name, d)
		}
		other := "replay-other"
		if !f.Decision("manned", &other).Enabled {
			t.Fatalf("%s: another adapter disabled", name)
		}
	}
	// Republish writes nothing when KV holds the database's state.
	if wrote, err := w.Republish(ctx); err != nil || wrote {
		t.Fatalf("republish %v %v", wrote, err)
	}
}
