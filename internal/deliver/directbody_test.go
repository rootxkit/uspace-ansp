package deliver

import (
	"encoding/json"
	"testing"
)

// The restriction/direct/v1 body: the version member is ansp_version
// (M4), the state and the feature are the version's; a version without
// what a receiver needs is refused, never served half empty.
func TestBuildDirect(t *testing.T) {
	v := version(3, "ended")
	raw, err := BuildDirect(v)
	if err != nil {
		t.Fatal(err)
	}
	var d DirectRestriction
	strict(t, raw, &d)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["version"]; ok {
		t.Fatal("the body names version, not ansp_version")
	}
	if d.Schema != DirectSchema || d.AnspVersion != 3 || d.State != "ended" || d.ID != testRID || d.Identifier != "DAR7K2Q" ||
		d.AnspRef != testRef || d.StartsAt != "2026-10-02T12:00:00.000Z" || d.EndsAt != "2026-10-02T16:00:00.000Z" || string(d.Feature) != testFeat {
		t.Fatalf("%+v", d)
	}
	for name, bad := range map[string]func(*VersionInfo){
		"no feature":    func(v *VersionInfo) { v.Feature = nil },
		"no ansp_ref":   func(v *VersionInfo) { v.AnspRef = "" },
		"no version":    func(v *VersionInfo) { v.Version = 0 },
		"bad feature":   func(v *VersionInfo) { v.Feature = json.RawMessage("{") },
		"no identifier": func(v *VersionInfo) { v.Identifier = "" },
	} {
		w := version(2, "active")
		bad(&w)
		if _, err := BuildDirect(w); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
}
