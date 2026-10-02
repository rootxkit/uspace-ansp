package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
