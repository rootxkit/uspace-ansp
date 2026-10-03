package schemas_test

// The JSON Schema validator github.com/santhosh-tekuri/jsonschema/v6 is
// used in tests only: the schemas use draft 2020-12 keywords (const,
// if/then, contains, prefixItems, $ref across files by $id) that a
// required-field list cannot check, and it is the validator uspace-lab
// and uspace-cisp check the same schemas with.

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-ansp/api/gen"
)

const idBase = "https://schemas.uspace.ge/"

// owned are the messages this system owns (M14), with the generated Go
// type each example round-trips through.
var owned = map[string]func() any{
	"track/manned/v1":         func() any { return new(gen.MannedTrackMessage) },
	"restriction/state/v1":    func() any { return new(gen.RestrictionStateMessage) },
	"coordination/annex_v/v1": func() any { return new(gen.AnnexVNotice) },
	"coordination/notice/v1":  func() any { return new(gen.CoordinationNoticeMessage) },
}

func readJSON(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

// compiler holds every schema of this directory (owned and common) by
// its $id, offline: a reference to a schema that is not here fails.
func compiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(offline{})
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") || strings.HasPrefix(filepath.ToSlash(p), "examples/") {
			return err
		}
		doc := readJSON(t, p)
		id, _ := doc.(map[string]any)["$id"].(string)
		if !strings.HasPrefix(id, idBase) {
			t.Fatalf("%s: $id %q", p, id)
		}
		return c.AddResource(id, doc)
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type offline struct{}

func (offline) Load(url string) (any, error) {
	return nil, &os.PathError{Op: "load", Path: url, Err: fs.ErrNotExist}
}

// Each owned schema sits at <family>/<name>/v1.json with the $id, title
// and schema name of that path.
func TestOwnedSchemasAreNamedByTheirPath(t *testing.T) {
	for name := range owned {
		doc := readJSON(t, filepath.FromSlash(name+".json")).(map[string]any)
		if doc["$id"] != idBase+name+".json" || doc["title"] != name || doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: $id %v, title %v, $schema %v", name, doc["$id"], doc["title"], doc["$schema"])
		}
		props, _ := doc["properties"].(map[string]any)
		schema, _ := props["schema"].(map[string]any)
		if schema["const"] != name {
			t.Errorf("%s: schema const %v", name, schema["const"])
		}
	}
}

// Every valid example validates and round-trips through its generated Go
// type with every member it had; every invalid example is refused; and
// every owned schema has both (E-01).
func TestExamplesBothWays(t *testing.T) {
	c := compiler(t)
	for name, newValue := range owned {
		sch, err := c.Compile(idBase + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		dir := filepath.Join("examples", filepath.FromSlash(name))
		valid, invalid := 0, 0
		err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			wantValid := filepath.Base(filepath.Dir(p)) != "invalid"
			err = sch.Validate(readJSON(t, p))
			switch {
			case wantValid && err != nil:
				t.Errorf("%s: refused: %v", p, err)
			case !wantValid && err == nil:
				t.Errorf("%s: an invalid example validated", p)
			case wantValid:
				valid++
				roundTrip(t, p, newValue())
			default:
				invalid++
				t.Logf("refused %s", filepath.ToSlash(p))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if valid == 0 || invalid == 0 {
			t.Errorf("%s: %d valid and %d invalid examples; both are required", name, valid, invalid)
		}
	}
}

// roundTrip decodes the example into v and encodes it again: every
// member path of the example is still there (the Go type drops nothing
// the schema names).
func roundTrip(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := lost(raw, v)
	if err != nil {
		t.Fatalf("%s: into %T: %v", path, v, err)
	}
	for _, k := range gone {
		t.Errorf("%s: %s is lost through %T", path, k, v)
	}
}

// lost is the member paths of raw that do not survive a round trip
// through v.
func lost(raw []byte, v any) ([]string, error) {
	if err := json.Unmarshal(raw, v); err != nil {
		return nil, err
	}
	again, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var before, after any
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(again, &after)
	kept := keys(after, "")
	var out []string
	for _, k := range keys(before, "") {
		if !slices.Contains(kept, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// E-01: the round trip reports a member a type drops (presence), so its
// silence on the generated types means something.
func TestRoundTripReportsALoss(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("examples", "track", "manned", "v1", "live-ads-b.json"))
	if err != nil {
		t.Fatal(err)
	}
	narrow := &struct {
		Schema string `json:"schema"`
	}{}
	gone, err := lost(raw, narrow)
	if err != nil || !slices.Contains(gone, "/body/icao24") {
		t.Fatalf("a narrow type lost nothing: %v %v", gone, err)
	}
	if gone, err := lost(raw, new(gen.MannedTrackMessage)); err != nil || len(gone) != 0 {
		t.Fatalf("the generated type lost %v (%v)", gone, err)
	}
}

// keys lists the member paths of a JSON value whose values are not null.
func keys(v any, prefix string) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if c == nil {
				continue
			}
			out = append(out, prefix+"/"+k)
			out = append(out, keys(c, prefix+"/"+k)...)
		}
	case []any:
		for _, c := range x {
			out = append(out, keys(c, prefix+"[]")...)
		}
	}
	return out
}

// The pinned common copies compile, and the envelope refuses what the
// owned schemas rely on it to refuse (absence) while accepting a valid
// frame (presence).
func TestCommonCopiesCompile(t *testing.T) {
	c := compiler(t)
	for _, name := range []string{"envelope/v1", "problem/v1", "source/status/v1", "console/status/v1", "console/snapshot/v1", "console/subscribe/v1", "track/telemetry/v1"} {
		if _, err := c.Compile(idBase + name + ".json"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	sch, err := c.Compile(idBase + "track/manned/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	frame := readJSON(t, filepath.Join("examples", "track", "manned", "v1", "live-ads-b.json")).(map[string]any)
	if err := sch.Validate(frame); err != nil {
		t.Fatal(err)
	}
	frame["msg_id"] = "not-a-ulid"
	if err := sch.Validate(frame); err == nil {
		t.Fatal("the envelope's msg_id rule did not apply to track/manned/v1")
	}
}
