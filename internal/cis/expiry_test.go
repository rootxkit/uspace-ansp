package cis_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// The tests of a restrictions version the CISP makes itself when a
// restriction passes its ends_at (spec 02 F3, erratum 2026-10-16; the
// numbers are the items of the cross-repo plan's required tests). Every
// hold is paired with the install it is the absence of.

// clock is the projection's and the store's clock, moved by the test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// expiryVerifier is core's detached verifier with the publishers' keys
// and, when cisp is set, the CISP's under PublisherCISP.
func expiryVerifier(t *testing.T, cisp bool) cis.PublisherVerifier {
	t.Helper()
	rings(t)
	pubs := map[string]coreauth.IssuerConfig{
		cis.PublisherAuthority: {Keys: authorityRing.JWKS()},
		cis.PublisherANSP:      {Keys: anspRing.JWKS()},
	}
	if cisp {
		pubs[cis.PublisherCISP] = coreauth.IssuerConfig{Keys: cispRing.JWKS()}
	}
	v, err := coreauth.NewDetachedVerifier(context.Background(), coreauth.DetachedConfig{Publishers: pubs, MaxAge: 366 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// expiryFixture is a projection holding all three datasets, the
// restrictions version in use v12 = {A ending endA, B ending endB},
// on a clock the test moves.
type expiryFixture struct {
	*fixtureProjection
	clk        *clock
	endA, endB time.Time
}

const skew = 30 * time.Second

func newExpiryFixture(t *testing.T, cisp bool) *expiryFixture {
	t.Helper()
	return newExpiryFixtureEndA(t, cisp, -10*time.Minute)
}

// newExpiryFixtureEndA is newExpiryFixture with A ending endA after the
// clock's start.
func newExpiryFixtureEndA(t *testing.T, cisp bool, endA time.Duration) *expiryFixture {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	fp := newProjection(t, func(c *cis.Config) {
		c.Publishers = expiryVerifier(t, cisp)
		c.Now = clk.now
		c.ExpirySkew = skew
	})
	fp.store.now = clk.now
	f := &expiryFixture{fixtureProjection: fp, clk: clk, endA: clk.now().Add(endA), endB: clk.now().Add(time.Hour)}
	fp.stub.publish(cis.USpaceAirspace, 3, fixture(t, cis.USpaceAirspace, 3), "publisher")
	fp.stub.publish(cis.USSPList, 2, fixture(t, cis.USSPList, 2), "publisher")
	fp.stub.publish(cis.Restrictions, 12, collection(t, 12, f.feature(t, "A", f.endA), f.feature(t, "B", f.endB)), "publisher")
	fp.pullAll(t)
	if fp.p.Version(cis.Restrictions) != 12 || fp.p.Provenance(cis.Restrictions) != cis.ProvenancePublisher {
		t.Fatalf("v12 not in use: %d %q", fp.p.Version(cis.Restrictions), fp.p.Provenance(cis.Restrictions))
	}
	return f
}

// feature is the restrictions fixture's feature as id, applying from an
// hour before end to end (the one period the CISP admits, darPeriod).
func (f *expiryFixture) feature(t *testing.T, id string, end time.Time) map[string]any {
	t.Helper()
	var doc struct {
		Features []map[string]any `json:"features"`
	}
	if err := json.Unmarshal(fixture(t, cis.Restrictions, 0), &doc); err != nil || len(doc.Features) != 1 {
		t.Fatalf("restrictions fixture: %v", err)
	}
	feat := doc.Features[0]
	feat["id"] = id
	props := feat["properties"].(map[string]any)
	props["identifier"] = id
	props["limitedApplicability"] = []any{map[string]any{
		"startDateTime": end.Add(-time.Hour).UTC().Format(time.RFC3339),
		"endDateTime":   end.UTC().Format(time.RFC3339),
	}}
	return feat
}

// collection is the restrictions dataset at version v holding features,
// as the CISP serves it.
func collection(t *testing.T, v int64, features ...map[string]any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixture(t, cis.Restrictions, 0), &m); err != nil {
		t.Fatal(err)
	}
	fs := make([]any, len(features))
	for i := range features {
		fs[i] = features[i]
	}
	m["features"] = fs
	m["cis_version"] = v
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// record is the CISP's expiry record; an empty featureID leaves
// feature_id and ends_at out, as a CISP before the erratum writes it.
func record(t *testing.T, op, featureID string, endsAt, at time.Time) []byte {
	t.Helper()
	m := map[string]string{"op": op, "restriction_id": "r-" + featureID, "at": at.UTC().Format(time.RFC3339Nano)}
	if featureID != "" {
		m["feature_id"] = featureID
		m["ends_at"] = endsAt.UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serveCISP makes version v of d the CISP's own: body at /versions/{v}
// with no X-Publisher-Signature and X-CIS-Signature by ring (nil: none)
// over sigBody (nil: body), and current at GET /v1/{dataset}.
func (f *expiryFixture) serveCISP(t *testing.T, d cis.Dataset, v int64, body, current []byte, ring *coreauth.KeyRing, sigBody []byte) {
	t.Helper()
	sd := &stubDataset{version: v, etag: fmt.Sprintf("%q", fmt.Sprintf("%s:%d", d, v)), body: body, current: current}
	if ring != nil {
		if sigBody == nil {
			sigBody = body
		}
		h, err := ring.SignDetached(sigBody, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		sd.cisSig = h
	}
	f.stub.mu.Lock()
	f.stub.ds[d] = sd
	f.stub.mu.Unlock()
}

// expire serves v13 = {B}, the CISP's expiry of A at at.
func (f *expiryFixture) expire(t *testing.T, at time.Time) {
	t.Helper()
	f.serveCISP(t, cis.Restrictions, 13, record(t, "expire", "A", f.endA, at), collection(t, 13, f.feature(t, "B", f.endB)), cispRing, nil)
}

func (f *expiryFixture) pull(t *testing.T) error {
	t.Helper()
	return f.p.Pull(context.Background(), cis.Restrictions, false)
}

// mustHold pulls and wants the version held with a reason containing
// want: v12 stays in use, unstored, its age not reset, the hold named
// in the status and counted.
func (f *expiryFixture) mustHold(t *testing.T, want string, expiry bool) {
	t.Helper()
	before, _ := f.store.row(cis.Restrictions)
	held, untrusted := f.p.Counters().Get(cis.CounterExpiryHeld), f.p.Counters().Get(cis.CounterUntrusted)
	var ue *cis.UntrustedError
	if err := f.pull(t); !errors.As(err, &ue) {
		t.Fatalf("not held: %v", err)
	}
	if !strings.Contains(ue.Reason, want) || ue.Expiry != expiry {
		t.Fatalf("reason %q (expiry %v), want %q (expiry %v)", ue.Reason, ue.Expiry, want, expiry)
	}
	if f.p.Version(cis.Restrictions) != 12 || f.p.Provenance(cis.Restrictions) != cis.ProvenancePublisher {
		t.Fatalf("version %d in use", f.p.Version(cis.Restrictions))
	}
	if after, _ := f.store.row(cis.Restrictions); after.Version != 12 || !after.FetchedAt.Equal(before.FetchedAt) {
		t.Fatalf("the hold moved cis_cache: %+v -> %+v", before, after)
	}
	if line := f.p.Status(context.Background(), f.clk.now()).Line(); !strings.Contains(line, "restrictions version") ||
		!strings.Contains(line, "held, not used") {
		t.Fatalf("status %s", line)
	}
	wantHeld := held
	if expiry {
		wantHeld++
	}
	if f.p.Counters().Get(cis.CounterExpiryHeld) != wantHeld || f.p.Counters().Get(cis.CounterUntrusted) != untrusted+1 ||
		f.p.Counters().Get(cis.CounterExpiryInstalled) != 0 {
		t.Fatalf("counters held %d untrusted %d installed %d", f.p.Counters().Get(cis.CounterExpiryHeld),
			f.p.Counters().Get(cis.CounterUntrusted), f.p.Counters().Get(cis.CounterExpiryInstalled))
	}
}

// mustInstall pulls and wants version v installed as a CISP expiry,
// with its age reset to the clock and nothing held.
func (f *expiryFixture) mustInstall(t *testing.T, v int64) {
	t.Helper()
	installed := f.p.Counters().Get(cis.CounterExpiryInstalled)
	if err := f.pull(t); err != nil {
		t.Fatalf("not installed: %v", err)
	}
	if f.p.Version(cis.Restrictions) != v || f.p.Provenance(cis.Restrictions) != cis.ProvenanceCISPExpiry {
		t.Fatalf("version %d (%q) in use, want %d", f.p.Version(cis.Restrictions), f.p.Provenance(cis.Restrictions), v)
	}
	if row, _ := f.store.row(cis.Restrictions); row.Version != v || !row.FetchedAt.Equal(f.clk.now()) {
		t.Fatalf("cis_cache %+v", row)
	}
	if f.p.Counters().Get(cis.CounterExpiryInstalled) != installed+1 {
		t.Fatal("cis_expiry_installed")
	}
	if line := f.p.Status(context.Background(), f.clk.now()).Line(); strings.Contains(line, "held") {
		t.Fatalf("status still names a hold: %s", line)
	}
}

// featureIDs is the identifiers of the restrictions version stored in
// cis_cache.
func (f *expiryFixture) featureIDs(t *testing.T) []string {
	t.Helper()
	row, _ := f.store.row(cis.Restrictions)
	v, rf := cis.ParseVersion(cis.Restrictions, row.Body, row.ETag, row.Version)
	if rf != nil {
		t.Fatal(rf)
	}
	var ids []string
	for i := range v.Collection.Features {
		ids = append(ids, v.Collection.Features[i].Properties.Identifier)
	}
	return ids
}

// 1. Acceptance: v13 = {B} with the CISP's signed expiry record of A is
// installed: version 13, A gone, nothing held, the age reset, the status
// not stale. The pair (no regression of chaining): v14, this system's
// signed end of B, then installs against v13 as a publisher version.
func TestExpiryInstalledThenChains(t *testing.T) {
	f := newExpiryFixture(t, true)
	f.clk.advance(200 * time.Second)
	f.expire(t, f.endA.Add(3*time.Second))
	f.mustInstall(t, 13)
	if ids := f.featureIDs(t); len(ids) != 1 || ids[0] != "B" {
		t.Fatalf("features in use %v", ids)
	}
	if n := len(f.stub.requests("GET", "/v1/restrictions/versions/13")); n != 1 {
		t.Fatalf("the expiry record was read %d times", n)
	}
	for _, d := range []cis.Dataset{cis.USpaceAirspace, cis.USSPList} {
		if err := f.p.Pull(context.Background(), d, false); err != nil {
			t.Fatal(err)
		}
	}
	if r := f.p.Status(context.Background(), f.clk.now()); r.State != cis.StateOK || r.AgeS != 0 {
		t.Fatalf("status %s", r.Line())
	}

	end, err := json.Marshal(map[string]any{"op": "end", "restriction_id": "r-B"})
	if err != nil {
		t.Fatal(err)
	}
	f.stub.publish(cis.Restrictions, 14, end, "publisher")
	f.stub.mu.Lock()
	f.stub.ds[cis.Restrictions].current = collection(t, 14)
	f.stub.mu.Unlock()
	if err := f.pull(t); err != nil {
		t.Fatalf("the ANSP's v14 after the expiry: %v", err)
	}
	if f.p.Version(cis.Restrictions) != 14 || f.p.Provenance(cis.Restrictions) != cis.ProvenancePublisher || len(f.featureIDs(t)) != 0 {
		t.Fatalf("v14: %d %q %v", f.p.Version(cis.Restrictions), f.p.Provenance(cis.Restrictions), f.featureIDs(t))
	}
	if f.p.Counters().Get(cis.CounterExpiryInstalled) != 1 {
		t.Fatal("v14 counted as an expiry")
	}
}

// 2. The CISP's signature: none, the ANSP's key, a key nobody
// configured, the bytes changed after signing, and the CISP's key not
// configured each hold. The pair is test 1: the same record signed by
// the CISP is installed.
func TestExpiryNeedsTheCISPSignature(t *testing.T) {
	f := newExpiryFixture(t, true)
	at := f.endA.Add(3 * time.Second)
	rec := record(t, "expire", "A", f.endA, at)
	served := collection(t, 13, f.feature(t, "B", f.endB))
	for _, tc := range []struct {
		name    string
		ring    *coreauth.KeyRing
		sigBody []byte
		want    string
	}{
		{"no signature", nil, nil, "no " + cis.HeaderCISSignature},
		{"the ANSP's key", anspRing, nil, cis.HeaderCISSignature + " does not verify"},
		{"another key", otherRing, nil, cis.HeaderCISSignature + " does not verify"},
		{"bytes changed after signing", cispRing, record(t, "expire", "A", f.endA, at.Add(time.Second)), cis.HeaderCISSignature + " does not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.serveCISP(t, cis.Restrictions, 13, rec, served, tc.ring, tc.sigBody)
			f.mustHold(t, tc.want, true)
		})
	}

	// Without a cisp entry in ANSP_CIS_PUBLISHER_KEYS (a configuration
	// before the erratum) the CISP's correctly signed record is held.
	g := newExpiryFixture(t, false)
	g.expire(t, g.endA.Add(3*time.Second))
	g.mustHold(t, cis.HeaderCISSignature+" does not verify with the cisp's keys", true)
	g2 := newExpiryFixture(t, true)
	g2.expire(t, g2.endA.Add(3*time.Second))
	g2.mustInstall(t, 13)
}

// 3. A removal before the signed end holds: A ending after at; after an
// extend (A's end moved later by this system's signed v13), an expiry
// whose at lies between the original and the extended end; at later
// than the clock plus cis_expiry_skew_s. The pairs: the expiry at the
// extended end is installed, and at one second inside the skew (A
// ending at at) is installed.
func TestExpiryBeforeTheSignedEndHeld(t *testing.T) {
	t.Run("removed before its end", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		f.expire(t, f.endA.Add(-time.Second))
		f.mustHold(t, `removes "A" before its signed end`, true)
	})
	t.Run("the original end after an extend", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		original := f.endA
		f.endA = original.Add(20 * time.Minute)
		extended := f.feature(t, "A", f.endA)
		req, err := json.Marshal(map[string]any{"op": "extend", "restriction_id": "r-A", "feature": extended})
		if err != nil {
			t.Fatal(err)
		}
		f.stub.publish(cis.Restrictions, 13, req, "publisher")
		f.stub.mu.Lock()
		f.stub.ds[cis.Restrictions].current = collection(t, 13, extended, f.feature(t, "B", f.endB))
		f.stub.mu.Unlock()
		if err := f.pull(t); err != nil || f.p.Version(cis.Restrictions) != 13 {
			t.Fatalf("the extend: %v", err)
		}
		f.serveCISP(t, cis.Restrictions, 14, record(t, "expire", "A", original, original.Add(5*time.Second)),
			collection(t, 14, f.feature(t, "B", f.endB)), cispRing, nil)
		var ue *cis.UntrustedError
		if err := f.pull(t); !errors.As(err, &ue) || !ue.Expiry || !strings.Contains(ue.Reason, `removes "A" before its signed end`) {
			t.Fatalf("an expiry at the pre-extension end: %v", err)
		}
		if f.p.Version(cis.Restrictions) != 13 {
			t.Fatal("the extended restriction's bookkeeping ended early")
		}
		f.serveCISP(t, cis.Restrictions, 14, record(t, "expire", "A", f.endA, f.endA.Add(time.Second)),
			collection(t, 14, f.feature(t, "B", f.endB)), cispRing, nil)
		f.clk.advance(21 * time.Minute)
		f.mustInstall(t, 14)
	})
	t.Run("at later than the clock plus the skew", func(t *testing.T) {
		f := newExpiryFixtureEndA(t, true, skew+time.Second)
		f.expire(t, f.endA)
		f.mustHold(t, "later than this system's clock plus cis_expiry_skew_s", true)
	})
	t.Run("at inside the skew", func(t *testing.T) {
		f := newExpiryFixtureEndA(t, true, skew-time.Second)
		f.expire(t, f.endA)
		f.mustInstall(t, 13)
	})
}

// 4. Content: a feature added, a feature changed (a member, or its
// window), nothing removed, and feature_id naming a feature that stays
// each hold. The pairs: test 1, and two removals in one jump.
func TestExpiryContentRule(t *testing.T) {
	for _, tc := range []struct {
		name    string
		served  func(f *expiryFixture) []byte
		feature string
		want    string
	}{
		{"a feature added", func(f *expiryFixture) []byte {
			return collection(t, 13, f.feature(t, "B", f.endB), f.feature(t, "C", f.endB))
		}, "A", `adds "C"`},
		{"a member changed", func(f *expiryFixture) []byte {
			b := f.feature(t, "B", f.endB)
			b["properties"].(map[string]any)["name"] = []any{map[string]any{"text": "not what the ANSP signed", "lang": "en-GB"}}
			return collection(t, 13, b)
		}, "A", `changes "B"`},
		{"a window changed", func(f *expiryFixture) []byte {
			return collection(t, 13, f.feature(t, "B", f.endB.Add(time.Minute)))
		}, "A", `changes "B"`},
		{"nothing removed", func(f *expiryFixture) []byte {
			return collection(t, 13, f.feature(t, "A", f.endA), f.feature(t, "B", f.endB))
		}, "A", "removes nothing"},
		{"feature_id stays", func(f *expiryFixture) []byte {
			return collection(t, 13, f.feature(t, "B", f.endB))
		}, "B", `feature_id "B" is not among the features it removes`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExpiryFixture(t, true)
			f.serveCISP(t, cis.Restrictions, 13, record(t, "expire", tc.feature, f.endA, f.endA.Add(3*time.Second)), tc.served(f), cispRing, nil)
			f.mustHold(t, tc.want, true)
		})
	}
	// v12 -> v15 while the pulls missed v13 and v14, two expiries: both
	// removed features ended, feature_id is one of them.
	t.Run("two removed in one jump", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		endB := f.endA.Add(time.Minute)
		c := f.feature(t, "C", f.endB)
		f.stub.publish(cis.Restrictions, 13, collection(t, 13, f.feature(t, "A", f.endA), f.feature(t, "B", endB), c), "publisher")
		if err := f.pull(t); err != nil || f.p.Version(cis.Restrictions) != 13 {
			t.Fatal(err)
		}
		f.serveCISP(t, cis.Restrictions, 15, record(t, "expire", "B", endB, endB.Add(time.Second)), collection(t, 15, c), cispRing, nil)
		f.mustInstall(t, 15)
		if ids := f.featureIDs(t); len(ids) != 1 || ids[0] != "C" {
			t.Fatalf("features in use %v", ids)
		}
	})
}

// A CISP before the erratum writes no feature_id and no ends_at: its
// expiry version is held as before the erratum, and the hold still
// names the missing publisher signature. The pair is test 1 (the same
// expiry from a CISP that writes feature_id).
func TestExpiryFromAnOlderCISPHeld(t *testing.T) {
	f := newExpiryFixture(t, true)
	f.serveCISP(t, cis.Restrictions, 13, record(t, "expire", "", time.Time{}, f.endA.Add(3*time.Second)),
		collection(t, 13, f.feature(t, "B", f.endB)), cispRing, nil)
	f.mustHold(t, "names no feature_id", true)
	var ue *cis.UntrustedError
	if err := f.pull(t); !errors.As(err, &ue) || !strings.HasPrefix(ue.Reason, "no "+cis.HeaderPublisherSignature) {
		t.Fatalf("the hold no longer names the missing publisher signature: %v", err)
	}
}

// 5. Replay and downgrade: once v13 is installed, the CISP serving v13
// again is a confirmation (no second read of the record, no reinstall);
// serving v12 is a counted replay; a CISP-made version numbered below
// the one in use is neither read nor installed.
func TestExpiryReplayAndDowngrade(t *testing.T) {
	f := newExpiryFixture(t, true)
	f.expire(t, f.endA.Add(3*time.Second))
	f.mustInstall(t, 13)
	installed, touches := f.p.Counters().Get(cis.CounterInstalled), f.store.touchs
	f.clk.advance(10 * time.Second)
	f.stub.mu.Lock()
	f.stub.ds[cis.Restrictions].etag = `"restrictions:13b"` // not a 304: the body is read again
	f.stub.mu.Unlock()
	if err := f.pull(t); err != nil {
		t.Fatal(err)
	}
	if f.p.Counters().Get(cis.CounterInstalled) != installed || f.store.touchs != touches+1 ||
		len(f.stub.requests("GET", "/v1/restrictions/versions/13")) != 1 {
		t.Fatal("v13 served again was not a plain confirmation")
	}
	if row, _ := f.store.row(cis.Restrictions); !row.FetchedAt.Equal(f.clk.now()) {
		t.Fatal("the confirmation did not move fetched_at")
	}

	f.stub.publish(cis.Restrictions, 12, collection(t, 12, f.feature(t, "A", f.endA), f.feature(t, "B", f.endB)), "publisher")
	if err := f.pull(t); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.Restrictions) != 13 || f.p.Counters().Get(cis.CounterVersionReplays) != 1 {
		t.Fatal("rolled back to v12")
	}

	f.serveCISP(t, cis.Restrictions, 11, record(t, "expire", "A", f.endA, f.endA.Add(3*time.Second)),
		collection(t, 11, f.feature(t, "B", f.endB)), cispRing, nil)
	if err := f.pull(t); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.Restrictions) != 13 || f.p.Counters().Get(cis.CounterVersionReplays) != 2 ||
		len(f.stub.requests("GET", "/v1/restrictions/versions/11")) != 0 || f.p.Counters().Get(cis.CounterExpiryInstalled) != 1 {
		t.Fatal("a lower CISP-made version was considered")
	}
}

// 6. The marker: a CISP-signed record with another op holds, as do
// CISP-signed bytes that are not a record; a uspace_airspace version
// with no publisher signature holds as before, CISP-signed or not, and
// is not judged as an expiry (the exception is the restrictions
// dataset's alone). The pair is test 1.
func TestExpiryMarker(t *testing.T) {
	t.Run("op end", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		f.serveCISP(t, cis.Restrictions, 13, record(t, "end", "A", f.endA, f.endA.Add(3*time.Second)),
			collection(t, 13, f.feature(t, "B", f.endB)), cispRing, nil)
		f.mustHold(t, `op "end", not expire`, true)
	})
	t.Run("not a record", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		f.serveCISP(t, cis.Restrictions, 13, []byte(`["expire"]`), collection(t, 13, f.feature(t, "B", f.endB)), cispRing, nil)
		f.mustHold(t, "not the CISP's expiry record", true)
	})
	t.Run("uspace_airspace", func(t *testing.T) {
		f := newExpiryFixture(t, true)
		f.serveCISP(t, cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), nil, cispRing, nil)
		held := f.p.Counters().Get(cis.CounterExpiryHeld)
		var ue *cis.UntrustedError
		if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.As(err, &ue) || ue.Expiry ||
			ue.Reason != "no "+cis.HeaderPublisherSignature {
			t.Fatalf("a CISP-signed designation: %v", err)
		}
		if f.p.Version(cis.USpaceAirspace) != 3 || f.p.Counters().Get(cis.CounterExpiryHeld) != held {
			t.Fatal("a designation judged as an expiry")
		}
	})
}

// 7. Staleness, the failure the erratum removes: with the expiry
// version held (today's CISP, no feature_id) the restrictions version in
// use ages past cis_stale_bound_s while the CISP answers every pull, and
// the readiness line turns stale naming the hold; with the expiry
// installed it stays ok.
func TestExpiryKeepsTheProjectionCurrent(t *testing.T) {
	bound := time.Duration(fixedPolicy(60)(context.Background()).CISStaleBoundS * float64(time.Second))
	for _, tc := range []struct {
		name      string
		featureID string
		want      string
	}{
		{"held", "", cis.StateStale},
		{"installed", "A", cis.StateOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExpiryFixture(t, true)
			f.serveCISP(t, cis.Restrictions, 13, record(t, "expire", tc.featureID, f.endA, f.endA.Add(3*time.Second)),
				collection(t, 13, f.feature(t, "B", f.endB)), cispRing, nil)
			for elapsed := time.Duration(0); elapsed <= bound; elapsed += time.Minute {
				f.clk.advance(time.Minute)
				for _, d := range cis.Datasets {
					_ = f.p.Pull(context.Background(), d, true)
				}
			}
			r := f.p.Status(context.Background(), f.clk.now())
			if r.State != tc.want {
				t.Fatalf("status %s, want %s", r.Line(), tc.want)
			}
			if tc.want == cis.StateStale && !strings.Contains(r.Line(), "names no feature_id") {
				t.Fatalf("the stale line does not name the hold: %s", r.Line())
			}
		})
	}
}

// E-03: the headers read are the pinned CISP contract's response
// headers of the version read (api/clients/cisp.yaml, getDatasetVersion).
func TestVersionHeadersPinned(t *testing.T) {
	b, err := os.ReadFile("../../api/clients/cisp.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "operationId: getDatasetVersion")
	if i < 0 {
		t.Fatal("getDatasetVersion is not in the pinned contract")
	}
	op := s[i:]
	if j := strings.Index(op[1:], "operationId:"); j > 0 {
		op = op[:j]
	}
	for _, h := range []string{cis.HeaderCISSignature, cis.HeaderPublisherSignature, cis.HeaderPublisherKID, cis.HeaderVersion} {
		if !strings.Contains(op, "\n            "+h+":") {
			t.Errorf("%s is not a response header of getDatasetVersion", h)
		}
	}
}
