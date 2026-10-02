// Package tests holds the repository layout rules (CLAUDE.md rule 6,
// docs/PLAN.md section 3) as a test.
package tests

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

const root = ".."

// dirs lists the directories directly under dir; a missing dir has none.
func dirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// Two migration trees, never a third and never merged (CLAUDE.md rule 6).
func TestMigrationTrees(t *testing.T) {
	for _, d := range dirs(t, "migrations") {
		if d != "relational" && d != "timeseries" {
			t.Errorf("migrations/%s: a third migration tree; there are exactly two, relational and timeseries", d)
		}
	}
}

// cmd/ holds exactly the three processes, the ones config accepts.
func TestCmdIsTheThreeProcesses(t *testing.T) {
	got := dirs(t, "cmd")
	want := slices.Clone(config.Processes)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("cmd/ has %v; the processes are %v (docs/PLAN.md section 3)", got, want)
	}
}

// web/ renders only: no Go file under it.
func TestNoGoUnderWeb(t *testing.T) {
	web := filepath.Join(root, "web")
	err := filepath.WalkDir(web, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") {
			t.Errorf("%s: web/ holds no Go code", filepath.ToSlash(p))
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// goFiles calls fn with every non-generated Go file under the module
// (web/ and vendor-like trees skipped) and its content.
func goFiles(t *testing.T, fn func(path, src string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "web" || strings.HasPrefix(d.Name(), ".")) && p != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(p), string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// No Go file imports lestrrat-go/jwx directly: every JWS is signed and
// verified through uspace-core/auth (M27, docs/PLAN.md section 4).
func TestNoDirectJWXImport(t *testing.T) {
	n := 0
	goFiles(t, func(p, src string) {
		n++
		if importsJWX(src) {
			t.Errorf("%s imports lestrrat-go/jwx directly; use uspace-core/auth", p)
		}
	})
	if n == 0 {
		t.Fatal("no Go file was read: the walk proves nothing")
	}
}

// The hot-path packages never import the control-plane ones (docs/PLAN.md
// section 3): manned-feed reaches the relational database through none
// of them; it writes TimescaleDB through store/timeseries only.
func TestHotPathImports(t *testing.T) {
	hot := []string{"manned", "picture", "feed", "sources", "policy", "bus", "cis"}
	cold := []string{"restriction", "deliver", "dss", "coord", "store", "store/relational"}
	checked := 0
	goFiles(t, func(p, src string) {
		rel := strings.TrimPrefix(p, "../")
		if strings.HasSuffix(p, "_test.go") {
			return // tests may wire a real store in
		}
		for _, h := range hot {
			if !strings.HasPrefix(rel, "internal/"+h+"/") {
				continue
			}
			checked++
			if c := coldImport(src, cold); c != "" {
				t.Errorf("%s (hot path) imports internal/%s", rel, c)
			}
		}
	})
	if checked == 0 {
		t.Fatal("no hot-path file was read")
	}
}

// importsJWX reports whether src imports lestrrat-go/jwx.
func importsJWX(src string) bool { return strings.Contains(src, `"github.com/`+`lestrrat-go/jwx`) }

// coldImport is the first of cold that src imports, or "".
func coldImport(src string, cold []string) string {
	for _, c := range cold {
		if strings.Contains(src, `"github.com/rootxkit/uspace-ansp/internal/`+c+`"`) {
			return c
		}
	}
	return ""
}

// The detectors above catch what they look for (presence), so the
// absence the walks assert means something.
func TestImportDetectors(t *testing.T) {
	if !importsJWX("import \"github.com/"+"lestrrat-go/jwx/v3/jws\"") || importsJWX(`import "github.com/rootxkit/uspace-core/auth"`) {
		t.Fatal("importsJWX")
	}
	cold := []string{"store", "store/relational"}
	if coldImport(`import "github.com/rootxkit/uspace-ansp/internal/store"`, cold) != "store" ||
		coldImport(`import "github.com/rootxkit/uspace-ansp/internal/store/relational"`, cold) != "store/relational" ||
		coldImport(`import "github.com/rootxkit/uspace-ansp/internal/store/timeseries"`, cold) != "" {
		t.Fatal("coldImport")
	}
}
