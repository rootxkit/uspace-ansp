//go:build integration

package main

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// Against a real NATS the api is ready, lists nats as ok and declares
// the streams and buckets (the presence pair of the unit test without
// NATS, E-01).
func TestIntegrationReadyWithNATS(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	addr := freeAddr(t)
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	env := []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + addr, "ANSP_NATS_URL=" + url}
	if creds := os.Getenv("ANSP_NATS_CREDS"); creds != "" {
		env = append(env, "ANSP_NATS_CREDS="+creds)
	}
	go func() { done <- run(ctx, nil, env, out) }()
	defer func() {
		cancel()
		if c := <-done; c != 0 {
			t.Errorf("exit %d", c)
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	for {
		code, body := get(t, "http://"+addr+"/readyz")
		if code == http.StatusOK && strings.Contains(body, `"nats: ok"`) && strings.Contains(out.String(), "streams and buckets declared") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz %d %s; log:\n%s", code, body, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The migrate subcommand against real databases: each tree from 0 to
// the newest version, said in the log; then the api refuses to start on
// a relational schema one migration behind, naming the tree and both
// versions (M36), and once current it starts and reports the database
// ready (the E-01 pair of the refusal).
func TestIntegrationMigrateThenStart(t *testing.T) {
	rel := storetest.Scratch(t, store.TreeRelational, false)
	ts := storetest.Scratch(t, store.TreeTimeseries, false)
	latest, err := store.Latest(store.TreeRelational)
	if err != nil {
		t.Fatal(err)
	}
	dbEnv := []string{"ANSP_PROCESS=" + process, "ANSP_RELATIONAL_DSN=" + rel, "ANSP_TIMESERIES_DSN=" + ts}
	out := &syncBuffer{}
	if code := run(context.Background(), []string{"migrate", "relational", "timeseries"}, dbEnv, out); code != 0 {
		t.Fatalf("migrate exit %d:\n%s", code, out.String())
	}
	want := `"tree":"relational","from_version":0,"version":` + strconv.FormatInt(latest, 10) + `,"applied":` + strconv.FormatInt(latest, 10)
	if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), `"tree":"timeseries","from_version":0`) {
		t.Fatalf("migrate log lacks %s:\n%s", want, out.String())
	}

	if err := store.DownTo(context.Background(), rel, store.TreeRelational, latest-1); err != nil {
		t.Fatal(err)
	}
	out = &syncBuffer{}
	env := append([]string{"ANSP_HTTP_ADDR=" + freeAddr(t)}, dbEnv...)
	if code := run(context.Background(), nil, env, out); code != 1 ||
		!strings.Contains(out.String(), "the relational tree is at version "+strconv.FormatInt(latest-1, 10)+", this build needs "+strconv.FormatInt(latest, 10)) {
		t.Fatalf("old schema: exit %d:\n%s", code, out.String())
	}

	if code := run(context.Background(), []string{"migrate", "relational"}, dbEnv, &syncBuffer{}); code != 0 {
		t.Fatal("re-migrate failed")
	}
	addr := freeAddr(t)
	env = append([]string{"ANSP_HTTP_ADDR=" + addr}, dbEnv...)
	out = &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, env, out) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, body := get(t, "http://"+addr+"/readyz")
		if strings.Contains(body, `"relational: ok"`) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("/readyz %s; log:\n%s", body, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if c := <-done; c != 0 {
		t.Fatalf("exit %d:\n%s", c, out.String())
	}
}
