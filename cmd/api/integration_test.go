//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

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
	versions, err := store.Versions(store.TreeRelational)
	if err != nil {
		t.Fatal(err)
	}
	// Versions are numbered in ranges per work package: the one below
	// the latest is not latest-1.
	latest, previous := versions[len(versions)-1], versions[len(versions)-2]
	dbEnv := []string{"ANSP_PROCESS=" + process, "ANSP_RELATIONAL_DSN=" + rel, "ANSP_TIMESERIES_DSN=" + ts}
	out := &syncBuffer{}
	if code := run(context.Background(), []string{"migrate", "relational", "timeseries"}, dbEnv, out); code != 0 {
		t.Fatalf("migrate exit %d:\n%s", code, out.String())
	}
	want := `"tree":"relational","from_version":0,"version":` + strconv.FormatInt(latest, 10) + `,"applied":` + strconv.Itoa(len(versions))
	if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), `"tree":"timeseries","from_version":0`) {
		t.Fatalf("migrate log lacks %s:\n%s", want, out.String())
	}

	if err := store.DownTo(context.Background(), rel, store.TreeRelational, previous); err != nil {
		t.Fatal(err)
	}
	out = &syncBuffer{}
	env := append([]string{"ANSP_HTTP_ADDR=" + freeAddr(t)}, dbEnv...)
	if code := run(context.Background(), nil, env, out); code != 1 ||
		!strings.Contains(out.String(), "the relational tree is at version "+strconv.FormatInt(previous, 10)+", this build needs "+strconv.FormatInt(latest, 10)) {
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

// With the session and secrets keys and a bootstrap admin the api
// serves the sign-in: the JWKS, login with the enrolment, the code, the
// session read back by /v1/auth/me, and a refusal without a session
// (E-01); /readyz still lists the relational database ok.
func TestIntegrationConsoleSignIn(t *testing.T) {
	rel := storetest.Scratch(t, store.TreeRelational, true)
	sk, sec, pwFile := authFiles(t)
	addr := freeAddr(t)
	env := []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + addr, "ANSP_MTLS_MODE=off", "ANSP_RELATIONAL_DSN=" + rel,
		"ANSP_SESSION_KEY_FILE=" + sk, "ANSP_SECRETS_KEY_FILE=" + sec, "ANSP_PUBLIC_BASE_URL=https://ansp.test",
		"ANSP_AUDIENCES=ansp.test,ansp-api", "ANSP_BOOTSTRAP_ADMIN_USERNAME=root", "ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE=" + pwFile}
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, env, out) }()
	defer func() {
		cancel()
		if c := <-done; c != 0 {
			t.Errorf("exit %d:\n%s", c, out.String())
		}
	}()
	base := "http://" + addr
	deadline := time.Now().Add(20 * time.Second)
	for {
		if code, _ := get(t, base+"/.well-known/jwks.json"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no JWKS; log:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "the first admin was created") || !strings.Contains(out.String(), "console sign-in mounted") {
		t.Fatalf("log:\n%s", out.String())
	}
	post := func(path, token string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	code, lr := post("/v1/auth/login", "", map[string]string{"username": "root", "password": "a long admin password"})
	if code != http.StatusOK || lr["enrolment"] == nil {
		t.Fatalf("login %d %v", code, lr)
	}
	secret := lr["enrolment"].(map[string]any)["secret"].(string)
	c, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	code, mr := post("/v1/auth/mfa", "", map[string]string{"mfa_token": lr["mfa_token"].(string), "code": c})
	if code != http.StatusOK || mr["token"] == nil {
		t.Fatalf("mfa %d %v", code, mr)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+mr["token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me %d", resp.StatusCode)
	}
	if code, _ := get(t, base+"/v1/auth/me"); code != http.StatusUnauthorized {
		t.Fatalf("me without a session: %d", code)
	}
	if code, _ := get(t, base+"/v1/users"); code != http.StatusUnauthorized {
		t.Fatalf("users without a session: %d", code)
	}
}
