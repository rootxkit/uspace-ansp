package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

func TestTrees(t *testing.T) {
	if len(Trees()) != 2 || TreeRelational.VersionTable != "goose_db_version_relational" ||
		TreeTimeseries.VersionTable != "goose_db_version_timeseries" || TreeRelational.LockID == TreeTimeseries.LockID {
		t.Fatalf("trees %+v", Trees())
	}
	for _, tree := range Trees() {
		got, ok := TreeByName(tree.Name)
		if !ok || got.Name != tree.Name {
			t.Fatalf("TreeByName(%s)", tree.Name)
		}
		v, err := Latest(tree)
		if err != nil || v < 1 {
			t.Fatalf("Latest(%s) = %d %v", tree.Name, v, err)
		}
		if _, err := fs.ReadFile(tree.FS(), "0001_extensions.sql"); err != nil {
			t.Fatalf("%s: %v", tree.Name, err)
		}
	}
	if _, ok := TreeByName("events"); ok {
		t.Fatal("a third tree")
	}
}

// Latest refuses a file not named NNNN_<slug>.sql and an empty tree.
func TestLatestRefusesMisnamedFiles(t *testing.T) {
	dir := t.TempDir()
	tree := Tree{Name: "test", fsys: os.DirFS(dir)}
	if _, err := Latest(tree); err == nil || !strings.Contains(err.Error(), "no migration") {
		t.Fatalf("empty: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0003_x.sql"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := Latest(tree); err != nil || v != 3 {
		t.Fatalf("one file: %d %v", v, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x_y.sql"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Latest(tree); err == nil || !strings.Contains(err.Error(), "x_y.sql") {
		t.Fatalf("misnamed: %v", err)
	}
	if _, err := Latest(Tree{Name: "missing", fsys: os.DirFS(filepath.Join(dir, "nope"))}); err == nil {
		t.Fatal("unreadable tree accepted")
	}
}

// LESSONS B-15: no migration of one tree names a table of the other.
// The test reads every CREATE TABLE of each tree and greps the other
// tree's files for those names as whole words; it is proved able to
// fail by the planted case below.
func TestTreesNeverReferenceEachOther(t *testing.T) {
	tables := map[string][]string{}
	texts := map[string]string{}
	create := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	for _, tree := range Trees() {
		entries, err := fs.ReadDir(tree.FS(), ".")
		if err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		for _, e := range entries {
			b, err := fs.ReadFile(tree.FS(), e.Name())
			if err != nil {
				t.Fatal(err)
			}
			all.Write(b)
			for _, m := range create.FindAllStringSubmatch(string(b), -1) {
				tables[tree.Name] = append(tables[tree.Name], m[1])
			}
		}
		texts[tree.Name] = all.String()
		if len(tables[tree.Name]) == 0 {
			t.Fatalf("%s: no table found; the scan is broken", tree.Name)
		}
	}
	cross := func(names []string, text string) []string {
		var hits []string
		for _, n := range names {
			if regexp.MustCompile(`\b` + n + `\b`).MatchString(text) {
				hits = append(hits, n)
			}
		}
		return hits
	}
	if hits := cross(tables["relational"], texts["timeseries"]); len(hits) > 0 {
		t.Errorf("the timeseries tree names relational tables %v", hits)
	}
	if hits := cross(tables["timeseries"], texts["relational"]); len(hits) > 0 {
		t.Errorf("the relational tree names timeseries tables %v", hits)
	}
	// The presence twin: a planted reference is found.
	if hits := cross(tables["timeseries"], "SELECT * FROM manned_tracks"); len(hits) != 1 {
		t.Fatalf("planted reference not found: %v", hits)
	}
}

func TestCheckVersion(t *testing.T) {
	if err := CheckVersion(TreeRelational, 6, 6); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion(TreeRelational, 7, 6); err != nil {
		t.Fatal(err)
	}
	err := CheckVersion(TreeTimeseries, 2, 3)
	if !errors.Is(err, ErrSchemaTooOld) || !strings.Contains(err.Error(), "timeseries tree is at version 2, this build needs 3") {
		t.Fatalf("%v", err)
	}
}

func TestSchemaVersion(t *testing.T) {
	if v, err := schemaVersion(TreeRelational, 5, nil); v != 5 || err != nil {
		t.Fatal(v, err)
	}
	boom := errors.New("boom")
	if _, err := schemaVersion(TreeRelational, 0, boom); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestFromConfig(t *testing.T) {
	pc := FromConfig(config.Config{Process: "api", DBMaxConns: 7, DBAcquireTimeoutS: 2, DBStatementTimeoutS: 3, DBTxTimeoutS: 9}, RoleRelational)
	if pc.MaxConns != 7 || pc.AcquireTimeout != 2*time.Second || pc.StatementTimeout != 3*time.Second ||
		pc.TxTimeout != 9*time.Second || pc.Role != "ansp_app" || pc.ApplicationName != "ansp-api" {
		t.Fatalf("%+v", pc)
	}
}

func goodPool() PoolConfig {
	return PoolConfig{MaxConns: 3, AcquireTimeout: time.Second, StatementTimeout: 2 * time.Second, TxTimeout: 5 * time.Second, Role: RoleRelational, ApplicationName: "ansp-test"}
}

// The bounds reach the server as runtime parameters; the role is set
// after connect.
func TestPgxConfig(t *testing.T) {
	cfg, err := goodPool().pgxConfig("postgres://u:secret@db:5432/ansp?sslmode=disable&connect_timeout=30")
	if err != nil {
		t.Fatal(err)
	}
	rp := cfg.ConnConfig.RuntimeParams
	if cfg.MaxConns != 3 || rp["statement_timeout"] != "2000" || rp["lock_timeout"] != "2000" ||
		rp["idle_in_transaction_session_timeout"] != "5000" || rp["application_name"] != "ansp-test" ||
		rp["timezone"] != "UTC" || cfg.AfterConnect == nil || cfg.ConnConfig.ConnectTimeout != time.Second {
		t.Fatalf("%+v %+v", cfg, rp)
	}
	noRole := goodPool()
	noRole.Role = ""
	if cfg, err := noRole.pgxConfig("postgres://db/ansp"); err != nil || cfg.AfterConnect != nil {
		t.Fatalf("no role: %v", err)
	}
}

func TestPoolConfigRefuses(t *testing.T) {
	_, err := PoolConfig{Role: "Bad Role"}.pgxConfig("postgres://db/ansp")
	for _, want := range []string{"max_conns", "acquire_timeout", "statement_timeout", "tx_timeout", "role"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %s in %v", want, err)
		}
	}
	_, err = goodPool().pgxConfig("postgres://u:secret@db:notaport/x")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("bad DSN: %v", err)
	}
	if _, err := OpenRelational(context.Background(), "postgres://u:secret@db:notaport/x", goodPool(), nil); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("open bad DSN: %v", err)
	}
	if _, err := OpenTimeseries(context.Background(), "::", PoolConfig{}, nil); err == nil {
		t.Fatal("open with no bounds")
	}
}

// An unreachable server is reported at open (as the role), not later,
// and within the acquire bound.
func TestOpenUnreachable(t *testing.T) {
	pc := goodPool()
	pc.AcquireTimeout = 500 * time.Millisecond
	start := time.Now()
	_, err := OpenRelational(context.Background(), "postgres://u:p@127.0.0.1:1/ansp?sslmode=disable", pc, &core.Counters{})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	_, err = OpenTimeseries(context.Background(), "postgres://u:p@127.0.0.1:1/ansp_ts?sslmode=disable", pc, nil)
	if err == nil {
		t.Fatal("unreachable timeseries accepted")
	}
}

func TestMigrateRefusesBadDSN(t *testing.T) {
	ctx := context.Background()
	if _, err := Migrate(ctx, "postgres://u:secret@db:notaport/x", TreeRelational); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("migrate: %v", err)
	}
	if err := DownTo(ctx, "postgres://u:secret@db:notaport/x", TreeRelational, 0); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("down: %v", err)
	}
	unreachable := "postgres://u:p@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"
	if _, err := Migrate(ctx, unreachable, TreeRelational); err == nil {
		t.Fatal("unreachable migrate accepted")
	}
	if err := DownTo(ctx, unreachable, TreeRelational, 0); err == nil {
		t.Fatal("unreachable down accepted")
	}
}

func TestLockKeyAndErrors(t *testing.T) {
	a1, a2, b := LockKey("a"), LockKey("a"), LockKey("b")
	if a1 == b || a1 != a2 {
		t.Fatal("lock keys")
	}
	if IsNoRows(errors.New("x")) || SQLState(errors.New("x")) != "" {
		t.Fatal("plain error")
	}
}

func TestGeometryRoundTrip(t *testing.T) {
	ring := geodesy.Ring{{LatDeg: 41.6, LonDeg: 44.7}, {LatDeg: 41.6, LonDeg: 44.9}, {LatDeg: 41.8, LonDeg: 44.9}, {LatDeg: 41.6, LonDeg: 44.7}}
	text, err := GeometryJSON(Geometry{Polygon: &geodesy.Polygon{Rings: []geodesy.Ring{ring}}})
	if err != nil || text != `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.6]]]}` {
		t.Fatalf("%s %v", text, err)
	}
	g, err := ParseGeometry(text)
	if err != nil || g.Polygon == nil || g.Point != nil || len(g.Polygon.Rings[0]) != 4 || g.Polygon.Rings[0][2] != ring[2] {
		t.Fatalf("%+v %v", g, err)
	}
	p := core.LatLon{LatDeg: 41.7, LonDeg: 44.8}
	text, err = GeometryJSON(Geometry{Point: &p})
	if err != nil || text != `{"type":"Point","coordinates":[44.8,41.7]}` {
		t.Fatalf("%s %v", text, err)
	}
	if g, err := ParseGeometry(text); err != nil || g.Point == nil || *g.Point != p {
		t.Fatalf("%+v %v", g, err)
	}
}

// Every refusal names a field and never panics, including past each
// bound (E-10).
func TestGeometryRefuses(t *testing.T) {
	big := `{"type":"Point","coordinates":[1,2],"x":"` + strings.Repeat("a", MaxGeometryBytes) + `"}`
	manyRings := `{"type":"Polygon","coordinates":[` + strings.Repeat(`[[0,0],[1,0],[1,1],[0,0]],`, MaxRings) + `[[0,0],[1,0],[1,1],[0,0]]]}`
	var verts strings.Builder
	verts.WriteString(`{"type":"Polygon","coordinates":[[`)
	for i := range MaxVertices + 1 {
		verts.WriteString(`[0,` + strconv.FormatFloat(float64(i)/1e5, 'f', -1, 64) + `],`)
	}
	verts.WriteString(`[0,0]]]}`)
	for name, text := range map[string]string{
		"too large":     big,
		"not json":      `{"type":`,
		"trailing":      `{"type":"Point","coordinates":[1,2]} x`,
		"line":          `{"type":"LineString","coordinates":[[1,2],[3,4]]}`,
		"no rings":      `{"type":"Polygon","coordinates":[]}`,
		"too many":      manyRings,
		"vertices":      verts.String(),
		"open ring":     `{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1]]]}`,
		"bad polygon":   `{"type":"Polygon","coordinates":"x"}`,
		"bad point":     `{"type":"Point","coordinates":"x"}`,
		"point range":   `{"type":"Point","coordinates":[200,100]}`,
		"long type":     `{"type":"` + strings.Repeat("x", 100) + `"}`,
		"empty polygon": `{"type":"Polygon","coordinates":[[]]}`,
	} {
		_, err := ParseGeometry(text)
		var fe *core.FieldError
		if !errors.As(err, &fe) || !strings.HasPrefix(fe.Field, "geometry") || len(err.Error()) > 300 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := core.LatLon{LatDeg: 100}
	for name, g := range map[string]Geometry{
		"neither":   {},
		"both":      {Point: &core.LatLon{}, Polygon: &geodesy.Polygon{}},
		"no rings":  {Polygon: &geodesy.Polygon{}},
		"bad ring":  {Polygon: &geodesy.Polygon{Rings: []geodesy.Ring{{{}, {}}}}},
		"bad point": {Point: &bad},
	} {
		if _, err := GeometryJSON(g); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
