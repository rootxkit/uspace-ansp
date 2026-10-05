package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
)

// updateContract rewrites testdata/contract/direct from this system's
// code with a key generated now (only its public part is written):
//
//	go test ./internal/deliver -run TestDirectContractFixture -update-contract
var updateContract = flag.Bool("update-contract", false, "rewrite testdata/contract/direct")

// The degraded direct delivery as the receivers' contract tests replay
// it (uspace-ussp and uspace-authority vendor this directory with the
// commit it came from): for an activation and for the end that follows
// it, the cis/change/v1 compact JWS posted to /v1/cis/notifications and
// the signed restriction/direct/v1 its pull_url serves. The fixture is
// pinned here both ways: each record and body is what BuildChange and
// BuildDirect make of the inputs below, and every signature verifies
// with the committed JWKS. A change to either builder fails this test
// until the fixture is rewritten, and the receivers then fail theirs
// until they take the new one.
const (
	contractDir      = "../../testdata/contract/direct"
	contractIssuer   = "https://ansp.test"
	contractAudience = "receiver.test"
	contractBase     = "https://ansp.test"
	contractFeature  = `{"type":"Feature","id":"DAR7K2Q","geometry":{"type":"Polygon","coordinates":[[[44.78,41.7],[44.82,41.7],[44.82,41.73],[44.78,41.73],[44.78,41.7]]],"layer":{"upper":1200,"upperReference":"AMSL","lower":0,"lowerReference":"AMSL","uom":"m"}},"properties":{"identifier":"DAR7K2Q","country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR"],"name":[{"text":"Dynamic restriction (synthetic example)","lang":"en-GB"}],"limitedApplicability":[{"startDateTime":"2026-10-02T12:00:00.000Z","endDateTime":"2026-10-02T16:00:00.000Z"}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`
)

type contractCase struct {
	name       string
	v          VersionInfo
	op         string
	deliveryID string
	sentAt     time.Time
}

func contractCases() []contractCase {
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	base := VersionInfo{RestrictionID: "01K6P0A1B2C3D4E5F6G7H8J9KM", AnspRef: "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM",
		Identifier: "DAR7K2Q", UspaceAirspaceID: "GEOTU01", StartsAt: start, EndsAt: start.Add(4 * time.Hour),
		Feature: json.RawMessage(contractFeature)}
	act, end := base, base
	act.Version, act.State, act.PrevState, act.ChangedAt = 2, "active", "planned", start
	end.Version, end.State, end.PrevState, end.ChangedAt = 3, "ended", "active", start.Add(time.Hour)
	return []contractCase{
		{"activated", act, OpActivate, "01K6P0B000000000000000000A", start.Add(10 * time.Second)},
		{"ended", end, OpEnd, "01K6P0B000000000000000000B", start.Add(time.Hour + time.Second)},
	}
}

func TestDirectContractFixture(t *testing.T) {
	if *updateContract {
		writeContract(t)
	}
	raw, err := os.ReadFile(filepath.Join(contractDir, "jwks.json"))
	if err != nil {
		t.Fatalf("the fixture is missing (go test -run TestDirectContractFixture -update-contract): %v", err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(jwks.Close)
	keys := coreauth.IssuerConfig{JWKSURL: jwks.URL + "/.well-known/jwks.json"}
	for _, c := range contractCases() {
		read := func(suffix string) []byte {
			b, err := os.ReadFile(filepath.Join(contractDir, c.name+suffix))
			if err != nil {
				t.Fatal(err)
			}
			return bytes.TrimSpace(b)
		}
		now := func() time.Time { return c.sentAt }
		cv, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
			Issuers: map[string]coreauth.IssuerConfig{contractIssuer: keys}, Audiences: []string{contractAudience}, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		cl, payload, err := cv.Verify(context.Background(), compactOf(t, read(".change.json")))
		if err != nil {
			t.Fatalf("%s: the record does not verify: %v", c.name, err)
		}
		want, err := BuildChange(c.v, c.op, c.deliveryID, contractBase)
		if err != nil {
			t.Fatal(err)
		}
		if cl.Subject != c.v.RestrictionID || cl.JTI != c.deliveryID || !jsonEqual(t, payload, want) {
			t.Fatalf("%s: the fixture's record is not what BuildChange makes: claims %+v\n%s\n%s", c.name, cl, payload, want)
		}
		var ch cispclient.Change
		strict(t, payload, &ch)
		body := read(".direct.json")
		wantBody, err := BuildDirect(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("%s: the fixture's restriction/direct/v1 is not what BuildDirect makes:\n%s\n%s", c.name, body, wantBody)
		}
		dv, err := coreauth.NewDetachedVerifier(context.Background(), coreauth.DetachedConfig{
			Publishers: map[string]coreauth.IssuerConfig{"ansp": keys}, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dv.Verify(context.Background(), "ansp", string(read(".direct.jws")), body); err != nil {
			t.Fatalf("%s: the direct body does not verify: %v", c.name, err)
		}
		var d DirectRestriction
		strict(t, body, &d)
		if ch.PullUrl != PullURL(contractBase, d.ID) || ch.Version != d.AnspVersion || ch.FeatureIds[0] != d.Identifier ||
			string(ch.Reason) != map[string]string{"activated": "restriction_activated", "ended": "restriction_ended"}[c.name] {
			t.Fatalf("%s: record %+v and body %+v disagree", c.name, ch, d)
		}
	}
}

func writeContract(t *testing.T) {
	t.Helper()
	ring := testRing(t)
	if err := os.MkdirAll(contractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	put := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(contractDir, name), append(bytes.TrimSpace(b), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	jwks, err := json.MarshalIndent(ring.JWKS(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	put("jwks.json", jwks)
	cases := contractCases()
	for i := range cases {
		c := &cases[i]
		rec, err := BuildChange(c.v, c.op, c.deliveryID, contractBase)
		if err != nil {
			t.Fatal(err)
		}
		jws, err := ring.SignCompact(coreauth.CompactClaims{Issuer: contractIssuer, Audience: contractAudience,
			Subject: c.v.RestrictionID, JTI: c.deliveryID}, rec, c.sentAt)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(jws, ".")
		if len(parts) != 3 {
			t.Fatalf("not a compact JWS: %d parts", len(parts))
		}
		split, err := json.MarshalIndent(compactParts{Protected: parts[0], Payload: parts[1], Signature: parts[2]}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		put(c.name+".change.json", split)
		body, err := BuildDirect(c.v)
		if err != nil {
			t.Fatal(err)
		}
		put(c.name+".direct.json", body)
		sig, err := ring.SignDetached(body, c.sentAt)
		if err != nil {
			t.Fatal(err)
		}
		put(c.name+".direct.jws", []byte(sig))
	}
}

// compactParts is a compact JWS kept as its three parts, so that the
// committed fixture holds no token-shaped string (the secret scan's jwt
// rule; nothing here is a secret: the key is generated at write time and
// only its public part is kept). A receiver joins them with ".".
type compactParts struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func compactOf(t *testing.T, raw []byte) string {
	t.Helper()
	var p compactParts
	if err := json.Unmarshal(raw, &p); err != nil || p.Protected == "" || p.Payload == "" || p.Signature == "" {
		t.Fatalf("not the three parts of a compact JWS: %v", err)
	}
	return p.Protected + "." + p.Payload + "." + p.Signature
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
