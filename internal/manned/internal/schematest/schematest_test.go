package schematest_test

import (
	"os"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
)

// The helper validates the repository's own valid example and refuses
// its invalid one (E-01), so a pass elsewhere means something.
func TestValidateBothWays(t *testing.T) {
	sch := schematest.Compile(t, schematest.TrackManned)
	good, err := os.ReadFile("../../../../schemas/examples/track/manned/v1/live-ads-b.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schematest.Validate(t, sch, good); err != nil {
		t.Fatal(err)
	}
	bad, _ := os.ReadFile("../../../../schemas/examples/track/manned/v1/invalid/icao24-upper-case.json")
	if err := schematest.Validate(t, sch, bad); err == nil {
		t.Fatal("an invalid example validated")
	}
	if schematest.Compile(t, schematest.SourceStatus) == nil {
		t.Fatal("no status schema")
	}
}
