package cis_test

import (
	"os"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// No panic on untrusted input (CLAUDE.md rule 10): any bytes as any
// dataset are a version or a refusal.
func FuzzParseVersion(f *testing.F) {
	for _, d := range cis.Datasets {
		if b, err := os.ReadFile("../../testdata/fixtures/" + string(d) + ".json"); err == nil {
			f.Add(b, uint8(0))
		}
	}
	f.Add([]byte(`{"type":"FeatureCollection","features":[],"cis_dataset":"restrictions","cis_version":1}`), uint8(2))
	f.Fuzz(func(t *testing.T, body []byte, which uint8) {
		d := cis.Datasets[int(which)%len(cis.Datasets)]
		v, rf := cis.ParseVersion(d, body, "", 0)
		if (v == nil) == (rf == nil) {
			t.Fatalf("version %v and refusal %v", v, rf)
		}
	})
}

// No panic on a KV value or push the follower reads.
func FuzzFollowerApply(f *testing.F) {
	f.Add([]byte(`{"dataset":"restrictions","version":1,"etag":"e","fetched_at":"2026-10-02T00:00:00Z"}`))
	f.Add([]byte(`{"dataset":"uspace_airspace","version":1,"etag":"e","fetched_at":"2026-10-02T00:00:00Z","body":{}}`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		cis.NewFollower(nil).ApplyJSON(raw)
	})
}
