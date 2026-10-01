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
