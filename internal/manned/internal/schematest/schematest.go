// Package schematest validates what the adapter puts on the wire
// against the schemas of this repository (schemas/, owned and pinned
// common copies), offline, with the validator the schemas package's
// tests use. It is imported by tests only.
package schematest

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const idBase = "https://schemas.uspace.ge/"

// The schema names the adapter produces.
const (
	TrackManned  = "track/manned/v1"
	SourceStatus = "source/status/v1"
)

type offline struct{}

// Load refuses every URL: the schemas are all added by $id.
func (offline) Load(url string) (any, error) {
	return nil, &os.PathError{Op: "load", Path: url, Err: fs.ErrNotExist}
}

// dir is the repository's schemas directory.
func dir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("schematest: no caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "schemas")
}

// Compile compiles the schema named name (e.g. "track/manned/v1").
func Compile(t testing.TB, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(offline{})
	root := dir(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") || strings.HasPrefix(filepath.ToSlash(rel), "examples/") {
			return err
		}
		raw, err := os.ReadFile(p) //nolint:gosec // G304: p is a file of this repository's schemas/ walked above
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		id, _ := doc.(map[string]any)["$id"].(string)
		return c.AddResource(id, doc)
	})
	if err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(idBase + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

// Validate is the validation error of the JSON document raw against sch
// (nil when it validates).
func Validate(t testing.TB, sch *jsonschema.Schema, raw []byte) error {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return sch.Validate(doc)
}
