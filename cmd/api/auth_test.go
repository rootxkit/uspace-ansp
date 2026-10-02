package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// authFiles writes a session key, a secrets key and an admin password
// generated for this test (06 section 4: no key in the repository).
func authFiles(t *testing.T) (sessionKey, secretsKey, adminPassword string) {
	t.Helper()
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey = filepath.Join(dir, "session.pem")
	secretsKey = filepath.Join(dir, "secrets.key")
	adminPassword = filepath.Join(dir, "admin.pw")
	seal := make([]byte, 32)
	_, _ = rand.Read(seal)
	for path, b := range map[string][]byte{
		sessionKey:    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}),
		secretsKey:    []byte(hex.EncodeToString(seal)),
		adminPassword: []byte("a long admin password\n"),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return sessionKey, secretsKey, adminPassword
}

// Console sign-in needs its database and keys: each missing piece is a
// refusal at start naming the variable (exit 2), never a process that
// serves sign-in half configured.
func TestRunRefusesIncompleteAuth(t *testing.T) {
	sk, _, _ := authFiles(t)
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"no database": {[]string{"ANSP_SESSION_KEY_FILE=" + sk}, "ANSP_RELATIONAL_DSN"},
		"issuer JWKS unreachable": {[]string{"ANSP_TOKEN_ISSUERS=https://authority.test=https://127.0.0.1:1/jwks", "ANSP_AUDIENCES=ansp.test"},
			"ANSP_TOKEN_ISSUERS"},
	} {
		t.Run(name, func(t *testing.T) {
			out := &syncBuffer{}
			env := append([]string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + freeAddr(t), "ANSP_MTLS_MODE=off"}, tc.env...)
			if code := run(context.Background(), nil, env, out); code != 2 || !strings.Contains(out.String(), tc.want) ||
				!strings.Contains(out.String(), `"msg":"auth refused"`) {
				t.Fatalf("exit %d; log:\n%s", code, out.String())
			}
		})
	}
}

// ANSP_MTLS_MODE=required needs bindings: without the file, or with an
// empty one, buildMTLS refuses naming ANSP_MTLS_BINDINGS_FILE; with
// bindings it builds a required binding, and off builds without any.
func TestBuildMTLS(t *testing.T) {
	dir := t.TempDir()
	empty, bound := filepath.Join(dir, "empty.json"), filepath.Join(dir, "bound.json")
	if err := os.WriteFile(empty, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bound, []byte(`[{"sub":"ussp-geo-01","subject":"CN=ussp-geo-01"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"no file": "", "empty file": empty} {
		if _, err := buildMTLS(config.Config{MTLSMode: config.MTLSRequired, MTLSBindingsFile: file}, nil); err == nil ||
			!strings.Contains(err.Error(), "ANSP_MTLS_BINDINGS_FILE") {
			t.Fatalf("required, %s: %v", name, err)
		}
	}
	m, err := buildMTLS(config.Config{MTLSMode: config.MTLSRequired, MTLSBindingsFile: bound}, nil)
	if err != nil || m.Mode() != config.MTLSRequired {
		t.Fatalf("required with bindings: %v", err)
	}
	m, err = buildMTLS(config.Config{MTLSMode: config.MTLSOff}, nil)
	if err != nil || m.Mode() != config.MTLSOff {
		t.Fatalf("off without bindings: %v", err)
	}
}

// The process refuses to start (exit 2) with ANSP_MTLS_MODE=required
// and no bindings, and starts with the same mode once bindings are
// configured.
func TestRunRequiredMTLSNeedsBindings(t *testing.T) {
	out := &syncBuffer{}
	env := []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + freeAddr(t), "ANSP_MTLS_MODE=required"}
	if code := run(context.Background(), nil, env, out); code != 2 || !strings.Contains(out.String(), "ANSP_MTLS_BINDINGS_FILE") ||
		!strings.Contains(out.String(), `"msg":"auth refused"`) {
		t.Fatalf("no bindings: exit %d; log:\n%s", code, out.String())
	}

	bound := filepath.Join(t.TempDir(), "bound.json")
	if err := os.WriteFile(bound, []byte(`[{"sub":"ussp-geo-01","subject":"CN=ussp-geo-01"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	out = &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, nil, []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + addr, "ANSP_MTLS_MODE=required", "ANSP_MTLS_BINDINGS_FILE=" + bound}, out)
	}()
	for deadline := time.Now().Add(10 * time.Second); ; {
		if code, _ := get(t, "http://"+addr+"/healthz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("with bindings: no /healthz; log:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case c := <-done:
		if c != 0 {
			t.Fatalf("with bindings: exit %d; log:\n%s", c, out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no drain")
	}
}
