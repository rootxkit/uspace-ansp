//go:build integration

package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
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
