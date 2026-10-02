package restriction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

type vectorInput struct {
	Kind          string                       `json:"kind"`
	Document      json.RawMessage              `json:"document"`
	ED269Document json.RawMessage              `json:"ed269_document"`
	Lang          string                       `json:"lang"`
	At            string                       `json:"at"`
	Where         json.RawMessage              `json:"where"`
	Daylight      map[string]map[string]string `json:"daylight"`
}

type vectorExpected struct {
	Accepted    *bool           `json:"accepted"`
	Export      json.RawMessage `json:"export"`
	MustInclude *struct {
		FieldEndsWith  string `json:"field_endswith"`
		ReasonContains string `json:"reason_contains"`
	} `json:"must_include"`
	Mapped         *bool           `json:"mapped"`
	ED269          json.RawMessage `json:"ed269"`
	ED318          json.RawMessage `json:"ed318"`
	FieldEndsWith  string          `json:"field_endswith"`
	ReasonContains string          `json:"reason_contains"`
	Applies        *bool           `json:"applies"`
	NotEvaluated   *bool           `json:"not_evaluated"`
}

// The ed318_roundtrip vectors that name ansp, run through this system's
// adapters: a parse case through CheckFeature (what every restriction
// feature passes before it leaves: ed318.Parse, then ed318.Export of
// what was read), a to_ed269 case through the constraint's geozone
// mapping (gap 16). from_ed269 and applies are not this system's
// judgement (it never imports ED-269 nor judges applicability) and are
// skipped with the reason.
func TestVectorsED318Roundtrip(t *testing.T) {
	f := vectors.Load(t, "ed318_roundtrip.json")
	counts := map[string]int{}
	f.RunOwned(t, "ansp", func(t *testing.T, c vectors.Case) {
		var in vectorInput
		var exp vectorExpected
		c.Decode(t, &in, &exp)
		counts[in.Kind]++
		switch in.Kind {
		case "parse":
			runParse(t, in, exp)
		case "to_ed269":
			runGeozone(t, in, exp)
		case "from_ed269", "applies":
			t.Skipf("%s: not a judgement of uspace-ansp (it publishes ED-318 restrictions only; applicability is the consumers')", in.Kind)
		default:
			t.Fatalf("unknown kind %q", in.Kind)
		}
	})
	t.Logf("cases by kind: %v", counts)
}

func runParse(t *testing.T, in vectorInput, exp vectorExpected) {
	t.Helper()
	fc, probs := ed318.Parse(in.Document, ed318.Limits{})
	if !*exp.Accepted {
		if probs == nil {
			t.Fatal("accepted, want refused")
		}
		for _, p := range probs.List {
			if strings.HasSuffix(p.Field, exp.MustInclude.FieldEndsWith) && strings.Contains(p.Reason, exp.MustInclude.ReasonContains) {
				return
			}
		}
		t.Fatalf("no problem ending %q containing %q", exp.MustInclude.FieldEndsWith, exp.MustInclude.ReasonContains)
	}
	if probs != nil {
		t.Fatalf("refused: %v", probs.List)
	}
	// Every feature passes this system's check, and the collection
	// exports equal by value to the expected export.
	var features []json.RawMessage
	for i := range fc.Features {
		raw, err := CheckFeature(&fc.Features[i])
		if err != nil {
			t.Fatalf("features[%d]: %v", i, err)
		}
		features = append(features, raw)
	}
	out, err := ed318.Export(fc)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, out, exp.Export) {
		t.Fatalf("export differs:\n%s\n%s", out, exp.Export)
	}
	var want struct {
		Features []json.RawMessage `json:"features"`
	}
	_ = json.Unmarshal(exp.Export, &want)
	for i := range features {
		if !jsonEqual(t, features[i], want.Features[i]) {
			t.Fatalf("features[%d] differs", i)
		}
	}
}

func runGeozone(t *testing.T, in vectorInput, exp vectorExpected) {
	t.Helper()
	fc, probs := ed318.Parse(in.Document, ed318.Limits{})
	if probs != nil {
		t.Fatalf("the input is refused: %v", probs.List)
	}
	if exp.Mapped != nil && !*exp.Mapped {
		// Refused by name: the first feature the mapping refuses makes the
		// constraint go without its geozone.
		_, err := ed318.ToED269(fc, in.Lang)
		if err == nil || !strings.Contains(err.Error(), exp.ReasonContains) {
			t.Fatalf("want %q, got %v", exp.ReasonContains, err)
		}
		for i := range fc.Features {
			if _, err := geozone(&fc.Features[i]); err != nil {
				return
			}
		}
		t.Fatal("every feature mapped, the collection did not")
	}
	for i := range fc.Features {
		if _, err := geozone(&fc.Features[i]); err != nil {
			t.Fatalf("features[%d]: %v", i, err)
		}
	}
}
