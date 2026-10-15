//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
)

// consoleSession is a session of this system as api issues it: signed
// with a session key the feed is started with, and live in
// sessions_live as api projects it.
func consoleSession(t *testing.T, b *bus.Bus, keyFile, sub, role string) string {
	t.Helper()
	sk, err := auth.LoadKeyFile("ANSP_SESSION_KEY_FILE", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := coreauth.NewKeyRing(sk)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := ring.Issuer("https://" + audience)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	jti := fmt.Sprintf("%032x", now.UnixNano())
	tok, err := iss.IssueSession(coreauth.SessionClaims{Audience: audience, Subject: sub, Roles: []string{role},
		Realm: auth.RealmConsole, IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: jti})
	if err != nil {
		t.Fatal(err)
	}
	(&auth.SessionProjector{KV: b.KeyValue(bus.BucketSessionsLive)}).Started(context.Background(), jti,
		auth.LiveSession{UserID: sub, Role: role, ExpiresAt: now.Add(time.Hour)})
	return tok
}

// GET /v1/manned-traffic/summary against real NATS: a console session
// (verified with the session key and sessions_live) reads the picture
// counted, empty with adapters_silent, then two live aircraft of a live
// adapter; a machine token with ansp.traffic is refused 403 and no
// credential 401.
func TestIntegrationFeedSummary(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "session.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600); err != nil {
		t.Fatal(err)
	}
	p := startFeed(t, "ANSP_SESSION_KEY_FILE="+keyFile, "ANSP_PUBLIC_BASE_URL=https://"+audience)
	session := consoleSession(t, p.b, keyFile, "user-summary-1", auth.RoleViewer)
	type summary struct {
		Total    int            `json:"total"`
		ByState  map[string]int `json:"by_state"`
		Relevant int            `json:"relevant"`
		Degraded []string       `json:"degraded"`
	}
	get := func(token string) (int, summary, string) {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, "http://"+p.addr+"/v1/manned-traffic/summary", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var s summary
		_ = json.Unmarshal(raw, &s)
		return resp.StatusCode, s, string(raw)
	}
	// The session reaches the feed once sessions_live holds it.
	deadline := time.Now().Add(20 * time.Second)
	var (
		code int
		s    summary
		raw  string
	)
	for {
		if code, s, raw = get(session); code == http.StatusOK || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	degraded := strings.Join(s.Degraded, ",")
	if code != http.StatusOK || s.Total != 0 || !strings.Contains(degraded, "adapters_silent") {
		t.Fatalf("empty: %d %s; log:\n%s", code, raw, p.out.String())
	}
	if code, _, raw := get(p.iss.token(t, "ussp-geo-01", "ansp.traffic")); code != http.StatusForbidden {
		t.Fatalf("machine token: %d %s", code, raw)
	}
	if code, _, _ := get(""); code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", code)
	}
	adapter := fmt.Sprintf("replay-sum-%d", time.Now().UnixNano()%100000)
	p.status(t, adapter, "live")
	now := time.Now().UTC()
	p.publish(t, liveSample(adapter, "a1b2c1", 41.70, 44.80, now))
	p.publish(t, liveSample(adapter, "a1b2c2", 41.71, 44.80, now))
	deadline = time.Now().Add(20 * time.Second)
	for {
		code, s, raw = get(session)
		if code == http.StatusOK && s.Total == 2 && s.ByState["live"] == 2 && !strings.Contains(strings.Join(s.Degraded, ","), "adapters_silent") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("two live aircraft not counted: %d %s", code, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(raw, "a1b2c1") {
		t.Fatalf("the summary names an aircraft: %s", raw)
	}
}
