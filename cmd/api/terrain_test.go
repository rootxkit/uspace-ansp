package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/terrain"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// writeTerrain writes a DEM directory in the lab fetch tool's layout:
// index.json naming N41E044, and N41E044.pgm, 5 x 5 samples at 0.25 deg
// from 42N 44E, elevation 580 + 20*row m (rows south). The tile is the
// PGM uspace-core's terrain.ParseTile reads (P5, the header as comment
// lines, 16-bit big-endian samples, elevation = Offset + Scale*raw); the
// test parses it with core before it is used, so a layout written wrong
// here fails here.
func writeTerrain(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var b bytes.Buffer
	b.WriteString("P5\n")
	f := func(x float64) string { return strconv.FormatFloat(x, 'g', -1, 64) }
	for _, h := range [][2]string{
		{"Description", "ansp test tile"}, {"Dataset", "COP-DEM GLO-30"},
		{"Offset", f(terrain.OffsetM)}, {"Scale", f(terrain.ScaleM)}, {"Nodata", "65535"},
		{"LatFirst", "42"}, {"LonFirst", "44"}, {"LatStep", "0.25"}, {"LonStep", "0.25"},
	} {
		b.WriteString("# " + h[0] + " " + h[1] + "\n")
	}
	b.WriteString("5 5\n65535\n")
	for row := 0; row < 5; row++ {
		for col := 0; col < 5; col++ {
			raw := uint16(math.Round((580 + 20*float64(row) - terrain.OffsetM) / terrain.ScaleM))
			b.WriteByte(byte(raw >> 8))
			b.WriteByte(byte(raw))
		}
	}
	if _, err := terrain.ParseTile(b.Bytes()); err != nil {
		t.Fatalf("the test tile does not parse in core: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "N41E044.pgm"), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"cells":{"N41E044":"COP-DEM GLO-30"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ANSP_TERRAIN_DIR is opened as the api process opens it: the index read
// now, the store answering the ground under a restriction's box, and a
// readiness check that names the cells indexed.
func TestTerrainLoaded(t *testing.T) {
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "info"})
	g, checks, err := loadTerrain(config.Config{TerrainDir: writeTerrain(t)}, logger)
	if err != nil || g == nil || len(checks) != 1 {
		t.Fatalf("loadTerrain: %v, %d checks, %v", g, len(checks), err)
	}
	r, err := g.RangeM(geodesy.BBox{MinLat: 41.70, MinLon: 44.78, MaxLat: 41.73, MaxLon: 44.82}, 0)
	if err != nil || r == nil || math.Abs(r.MinM-600) > 1e-9 || math.Abs(r.MaxM-620) > 1e-9 {
		t.Fatalf("range %+v %v", r, err)
	}
	// Ground outside the index is unknown, never zero.
	if r, err := g.RangeM(geodesy.BBox{MinLat: 40.5, MinLon: 44.5, MaxLat: 40.6, MaxLon: 44.6}, 0); err != nil || r != nil {
		t.Fatalf("outside the index: %+v %v", r, err)
	}
	rep := (&obs.Health{Process: process}).Check(context.Background(), checks...)
	if rep.Status != obs.StatusReady || len(rep.Summary) != 1 || rep.Summary[0] != "terrain: ok (1 cells indexed)" || checks[0].Required {
		t.Fatalf("/readyz %+v", rep)
	}
	if !strings.Contains(out.String(), `"terrain_cells":1`) {
		t.Fatalf("start log:\n%s", out.String())
	}
}

// Without ANSP_TERRAIN_DIR nothing is opened and nothing is checked, and
// the log says what is refused; an index that does not read or parse
// refuses the start, naming the variable.
func TestTerrainNotLoaded(t *testing.T) {
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "info"})
	g, checks, err := loadTerrain(config.Config{}, logger)
	if err != nil || g != nil || checks != nil || !strings.Contains(out.String(), "ANSP_TERRAIN_DIR is not set") {
		t.Fatalf("unset: %v %v %v %s", g, checks, err, out.String())
	}
	empty := t.TempDir()
	if g, _, err := loadTerrain(config.Config{TerrainDir: empty}, logger); err == nil || g != nil || !strings.Contains(err.Error(), "ANSP_TERRAIN_DIR") || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("no index: %v %v", g, err)
	}
	if err := os.WriteFile(filepath.Join(empty, "index.json"), []byte(`{"cells":{"X":"a"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var fe *core.FieldError
	g, _, err = loadTerrain(config.Config{TerrainDir: empty}, logger)
	if g != nil || err == nil || !strings.Contains(err.Error(), "does not parse") || !errors.As(err, &fe) || fe.Field != "ANSP_TERRAIN_DIR" {
		t.Fatalf("bad index: %v %v", g, err)
	}
}
