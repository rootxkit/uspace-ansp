//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// manned-feed migrates the timeseries tree, refuses to start on an
// empty database (version 0, naming the tree), and once migrated starts
// with the timeseries database ready (E-01 pair).
func TestIntegrationMigrateThenStart(t *testing.T) {
	ts := storetest.Scratch(t, store.TreeTimeseries, false)
	dbEnv := []string{"ANSP_PROCESS=" + process, "ANSP_TIMESERIES_DSN=" + ts, "ANSP_MTLS_MODE=off"}
	out := &syncBuffer{}
	env := append([]string{"ANSP_HTTP_ADDR=" + freeAddr(t)}, dbEnv...)
	if code := run(context.Background(), nil, env, out); code != 1 || !strings.Contains(out.String(), "the timeseries tree is at version 0") {
		t.Fatalf("empty database: exit %d:\n%s", code, out.String())
	}
	if code := run(context.Background(), []string{"migrate", "timeseries"}, dbEnv, out); code != 0 {
		t.Fatalf("migrate:\n%s", out.String())
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
		if strings.Contains(body, `"timeseries: ok"`) {
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
