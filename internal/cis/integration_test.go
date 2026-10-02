//go:build integration

package cis_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// cis_cache over the real database: a version is stored with the
// database's fetched_at, a 304 moves it, and a lower version never
// replaces a higher one.
func TestIntegrationCISRepo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db := storetest.Relational(t, storetest.Scratch(t, store.TreeRelational, true), store.RoleRelational)
	repo := store.CISRepo{DB: db}
	v3, rf := cis.ParseVersion(cis.USpaceAirspace, fixture(t, cis.USpaceAirspace, 3), `"uspace_airspace:3"`, 3)
	if rf != nil {
		t.Fatal(rf)
	}
	at, newer, err := repo.Save(ctx, v3)
	if err != nil || newer || at.IsZero() {
		t.Fatalf("save: %v %v %v", at, newer, err)
	}
	t2, ok, err := repo.Touch(ctx, cis.USpaceAirspace, 3)
	if err != nil || !ok || !t2.After(at) {
		t.Fatalf("touch: %v %v %v", t2, ok, err)
	}
	if _, ok, err := repo.Touch(ctx, cis.USpaceAirspace, 2); err != nil || ok {
		t.Fatal("touched another version")
	}
	v2, _ := cis.ParseVersion(cis.USpaceAirspace, fixture(t, cis.USpaceAirspace, 2), `"uspace_airspace:2"`, 2)
	if _, newer, err := repo.Save(ctx, v2); err != nil || !newer {
		t.Fatalf("a lower version was stored: %v %v", newer, err)
	}
	v4, _ := cis.ParseVersion(cis.USpaceAirspace, fixture(t, cis.USpaceAirspace, 4), `"uspace_airspace:4"`, 4)
	if _, newer, err := repo.Save(ctx, v4); err != nil || newer {
		t.Fatalf("a higher version was not stored: %v %v", newer, err)
	}
	rows, err := repo.Load(ctx)
	if err != nil || len(rows) != 1 || rows[0].Version != 4 || rows[0].ETag != `"uspace_airspace:4"` {
		t.Fatalf("load: %+v %v", rows, err)
	}
	if _, rf := cis.ParseVersion(cis.USpaceAirspace, rows[0].Body, rows[0].ETag, 4); rf != nil {
		t.Fatalf("the stored body no longer parses: %v", rf)
	}
}

// Pull -> cis_cache -> KV cis_current -> the hot path's follower, over
// the real database and NATS; the reconciliation reaches the follower
// too, and a restarted projection serves cis_cache before its first pull.
func TestIntegrationNotificationToFollower(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db := storetest.Relational(t, storetest.Scratch(t, store.TreeRelational, true), store.RoleRelational)
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, Name: "cis-test"}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	kv := b.KeyValue(bus.BucketCISCurrent)
	for _, d := range cis.Datasets {
		_ = kv.Delete(ctx, string(d))
	}

	s := newStub(t)
	s.publishAll()
	repo := store.CISRepo{DB: db}
	p := cis.New(cis.Config{Client: s.client(t), Publishers: publisherVerifier(t), Store: repo, KV: kv, Push: b.Conn(),
		Policy: fixedPolicy(1), CallbackURL: "https://" + ourHost + cis.NotificationsPath})
	pctx, pcancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { p.Run(pctx) })

	fol := cis.NewFollower(nil)
	if fol.Status(time.Now()) != cis.StatusNoProjection || len(fol.USpaceVolumes()) != 0 {
		t.Fatal("the follower is not empty at start")
	}
	wg.Go(func() { _ = fol.Run(pctx, kv) })
	waitFor(t, 10*time.Second, "the follower to take the first pull", func() bool { return fol.Version() == "3" && len(fol.USSPs()) == 2 })
	waitFor(t, 5*time.Second, "the subscription", func() bool { return p.SubscriptionID() != "" })

	// The reconciliation path: no notification, the next tick.
	s.publish(cis.USpaceAirspace, 5, fixture(t, cis.USpaceAirspace, 5), "publisher")
	waitFor(t, 5*time.Second, "version 5 by reconciliation", func() bool { return fol.Version() == "5" })
	pcancel()
	wg.Wait()

	// A restart serves cis_cache before any pull.
	again := cis.New(cis.Config{Store: repo})
	again.Warm(ctx)
	if ver, at, _, err := again.USpaceAirspace(); err != nil || ver != "5" || at.IsZero() {
		t.Fatalf("warm: %v %v %v", ver, at, err)
	}
}
