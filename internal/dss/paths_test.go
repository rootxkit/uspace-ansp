package dss

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// sourceValue is key's value in uspace-core's f3548/SOURCE (the module
// this build uses, found by the go command).
func sourceValue(t *testing.T, key string) string {
	t.Helper()
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go command is needed to find uspace-core: %v", err)
	}
	dir, err := exec.Command(gocmd, "list", "-m", "-f", "{{.Dir}}", "github.com/rootxkit/uspace-core").Output()
	if err != nil || len(bytes.TrimSpace(dir)) == 0 {
		t.Fatalf("uspace-core not found: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(string(bytes.TrimSpace(dir)), "f3548", "SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %s in uspace-core's f3548/SOURCE", key)
	return ""
}

// Every DSS path and member is traceable to the pinned utm.yaml (E-03):
// Operations equals the lines extracted from that file, and the file's
// URL and SHA-256 named in the excerpt (and in paths.go) are the ones
// uspace-core's f3548/SOURCE pins.
func TestOperationsAreThePinnedStandard(t *testing.T) {
	f, err := os.Open("testdata/utm-constraint-operations.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	pins := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "#"); ok {
			if k, v, ok := strings.Cut(rest, "="); ok {
				pins[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	for _, key := range []string{"spec_url", "spec_sha256"} {
		want := sourceValue(t, key)
		if pins[key] != want {
			t.Errorf("the excerpt's %s is %q; uspace-core pins %q", key, pins[key], want)
		}
	}
	src, err := os.ReadFile("paths.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"spec_commit", "spec_sha256"} {
		if v := sourceValue(t, key); !strings.Contains(strings.ReplaceAll(string(src), "\n// ", ""), v) {
			t.Errorf("paths.go does not cite uspace-core's %s %s", key, v)
		}
	}
	if len(lines) != len(Operations) {
		t.Fatalf("%d operations in the excerpt, %d in the table", len(lines), len(Operations))
	}
	for i, o := range Operations {
		scopes := make([]string, 0, len(o.Scopes))
		for _, s := range o.Scopes {
			scopes = append(scopes, string(s))
		}
		got := strings.Join([]string{o.ID, o.Method, o.Path, strings.Join(scopes, ","), strconv.Itoa(o.Success)}, " ")
		if got != lines[i] {
			t.Errorf("operation %d:\n table   %s\n utm.yaml %s", i, got, lines[i])
		}
	}
}

// Each id the package uses is in the table; an id that is not answers
// the zero operation, never a panic.
func TestOpAndPaths(t *testing.T) {
	for _, id := range []string{OpGetReference, OpCreateReference, OpUpdateReference, OpDeleteReference, OpNotifyDetails, OpGetDetails} {
		if Op(id).ID != id {
			t.Errorf("%s not in the table", id)
		}
	}
	if o := Op("nope"); o.ID != "" || o.Scope() != "" {
		t.Fatalf("unknown op %+v", o)
	}
	id := "2f8343be-6482-4d1b-a474-16847e01af1e"
	if p := ReferencePath(id, nil); p != "/dss/v1/constraint_references/"+id {
		t.Fatal(p)
	}
	ovn := "a/b c"
	if p := ReferencePath(id, &ovn); p != "/dss/v1/constraint_references/"+id+"/a%2Fb%20c" {
		t.Fatalf("the ovn is one escaped segment: %s", p)
	}
	if NotifyPath() != "/uss/v1/constraints" {
		t.Fatal(NotifyPath())
	}
	if Op(OpNotifyDetails).Scope() != "utm.constraint_management" || Op(OpCreateReference).Scope() != "utm.constraint_management" {
		t.Fatal("scopes")
	}
}
