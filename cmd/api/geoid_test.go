package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// writeGeoid writes a constant GeographicLib grid (N = 20 m everywhere).
func writeGeoid(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("P5\n# Description ansp test grid, N = 20 m\n# Offset 20\n# Scale 1\n2 3\n65535\n")
	b.Write(make([]byte, 2*2*3))
	path := filepath.Join(t.TempDir(), "geoid.pgm")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// checkGeoidLoad loads ANSP_GEOID_FILE as the api process does
// (wireRestrictions) and checks that the grid says wantMapped, in the
// start log and on /readyz (WP-19). geoid_unix_test.go wants a mapping,
// geoid_other_test.go the read into memory core falls back to elsewhere.
func checkGeoidLoad(t *testing.T, wantMapped bool) {
	t.Helper()
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "info"})
	g, checks, err := loadGeoid(config.Config{GeoidFile: writeGeoid(t)}, logger)
	if err != nil || g == nil || len(checks) != 1 {
		t.Fatalf("loadGeoid: %v, %d checks, %v", g, len(checks), err)
	}
	if n, err := g.UndulationM(core.LatLon{LatDeg: 41.7, LonDeg: 44.8}); err != nil || n != 20 {
		t.Fatalf("N %v, %v", n, err)
	}
	want := "geoid: ok (mapped: false)"
	logWant := `"geoid_mapped":false`
	if wantMapped {
		want, logWant = "geoid: ok (mapped: true)", `"geoid_mapped":true`
	}
	rep := (&obs.Health{Process: process}).Check(context.Background(), checks...)
	if rep.Status != obs.StatusReady || len(rep.Summary) != 1 || rep.Summary[0] != want || checks[0].Required {
		t.Fatalf("/readyz %+v, want %q", rep, want)
	}
	if !strings.Contains(out.String(), logWant) {
		t.Fatalf("start log lacks %s:\n%s", logWant, out.String())
	}
}

// Without ANSP_GEOID_FILE nothing is opened and nothing is checked; a
// file that does not load refuses the start, naming the variable.
func TestGeoidNotLoaded(t *testing.T) {
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "info"})
	g, checks, err := loadGeoid(config.Config{}, logger)
	if err != nil || g != nil || checks != nil || !strings.Contains(out.String(), "ANSP_GEOID_FILE is not set") {
		t.Fatalf("unset: %v %v %v %s", g, checks, err, out.String())
	}
	bad := filepath.Join(t.TempDir(), "geoid.pgm")
	if err := os.WriteFile(bad, []byte("not a grid"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, checks, err = loadGeoid(config.Config{GeoidFile: bad}, logger)
	if err == nil || g != nil || checks != nil || !strings.Contains(err.Error(), "ANSP_GEOID_FILE") {
		t.Fatalf("bad: %v %v %v", g, checks, err)
	}
}
