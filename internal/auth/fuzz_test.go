package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Untrusted input never panics (CLAUDE.md rule 10): the Authorization
// header and the cookie through the guard, and the decoders of peer
// answers, configuration files and stored hashes.
func FuzzGuardHeaders(f *testing.F) {
	for _, s := range []string{"", "Bearer ", "Bearer a.b.c", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2Fuc3AudGVzdCJ9.x", "Basic x"} {
		f.Add(s, "https://ansp.test", s)
	}
	w := newWorld(f)
	mw := w.guard.RequireUpgrade(Access{Scopes: []string{"ansp.traffic"}, AnyRole: true})
	h := mw(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }))
	f.Fuzz(func(t *testing.T, authz, origin, cookie string) {
		r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/stream", nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		r.Header.Set("Origin", origin)
		if cookie != "" && !strings.ContainsAny(cookie, ";\r\n\x00") {
			r.Header.Set("Cookie", CookieSession+"="+cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK {
			t.Fatalf("admitted %q %q", authz, cookie)
		}
	})
}

func FuzzParsers(f *testing.F) {
	f.Add([]byte(`[{"sub":"a","subject":"CN=a"}]`), 200, "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$dGFndGFndGFndGFndGFn", "10.0.0.1, 1.2.3.4")
	f.Add([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":60}`), 400, "", "")
	f.Fuzz(func(_ *testing.T, raw []byte, status int, hash, xff string) {
		_, _ = ParseMTLSBindings(raw)
		_, _, _ = ParseTokenResponse(status, raw)
		_ = unverifiedIssuer(string(raw))
		_, _, _, _ = decodeHash(hash) // the parser only: a parsed hash may ask for up to maxMemoryKiB
		_ = ClientIP("10.0.0.2:1", []string{xff}, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
		_, _ = VerifyTOTP("JBSWY3DPEHPK3PXP", string(raw), time.Unix(1790000000, 0), 0)
		_, _ = AudienceOf(xff)
	})
}
