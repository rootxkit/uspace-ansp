package feed

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fixedPolicy struct{ p policy.Policy }

func (f fixedPolicy) Current() (policy.Policy, bool) { return f.p, true }

func defaultPolicy() fixedPolicy {
	return fixedPolicy{policy.Policy{Version: 3, Thresholds: policy.Defaults()}}
}

func f64(v float64) *float64 { return &v }

// sample is a track as the adapter publishes it.
func sample(icao, instance string, lat, lon float64, at time.Time) manned.Track {
	cs, sq := "TST123", "4521"
	return manned.Track{
		Schema: manned.SchemaTrack, MsgID: manned.NewULID(at), Producer: manned.Producer,
		Times: core.Times{TS: &at, RxTS: at.Add(100 * time.Millisecond), CapturedAt: at, Source: core.TimeReceiver},
		Trust: core.TrustSurveillance, Source: manned.SourceANSPFeed, SourceInstance: instance, ICAO24: icao,
		Callsign: &cs, Position: core.LatLon{LatDeg: lat, LonDeg: lon}, AltPressureM: f64(1524), GSMS: f64(72.5),
		TrackDeg: f64(134), VRateMS: f64(-2.5), Squawk: &sq, SourceClass: manned.SourceClassADSB,
		Quality: map[string]any{"nic": 8.0}, PolicyVersion: 1,
	}
}

func wireOf(t testing.TB, tr manned.Track) []byte {
	t.Helper()
	b, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// statusMsg is a source/status/v1 message as the adapter publishes it.
func statusMsg(instance, state string, enabled bool, lastFrame time.Time) []byte {
	lf := manned.FormatTime(lastFrame)
	return []byte(`{"schema":"source/status/v1","msg_id":"` + manned.NewULID(lastFrame) + `","producer":"ansp/manned-adapter","ts":null,` +
		`"rx_ts":"` + lf + `","captured_at":"` + lf + `","time_source":"system","backlog":false,"body":{"source":"ansp_feed",` +
		`"source_instance":"` + instance + `","state":"` + state + `","since":"` + lf + `","age_s":0.4,"disabled_by":null,` +
		`"disabled_by_who":null,"counters":{"accepted":10,"refused":0},"enabled":` + map[bool]string{true: "true", false: "false"}[enabled] +
		`,"last_frame_at":"` + lf + `"}}`)
}

const idBase = "https://schemas.uspace.ge/"

type offline struct{}

func (offline) Load(url string) (any, error) {
	return nil, &os.PathError{Op: "load", Path: url, Err: fs.ErrNotExist}
}

// compile compiles a schema of this repository's schemas/ offline.
func compile(t testing.TB, name string) *jsonschema.Schema {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "schemas")
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(offline{})
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") || strings.HasPrefix(filepath.ToSlash(rel), "examples/") {
			return err
		}
		raw, err := os.ReadFile(p)
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

// frameSchemas validates a server frame by its schema (dispatching on
// it, as a consumer does).
type frameSchemas struct {
	envelope *jsonschema.Schema
	byName   map[string]*jsonschema.Schema
}

func newFrameSchemas(t testing.TB) *frameSchemas {
	return &frameSchemas{envelope: compile(t, "envelope/v1"), byName: map[string]*jsonschema.Schema{
		"track/manned/v1":     compile(t, "track/manned/v1"),
		"console/status/v1":   compile(t, "console/status/v1"),
		"console/snapshot/v1": compile(t, "console/snapshot/v1"),
	}}
}

// check validates raw against the envelope and its own schema and
// returns the schema name.
func (f *frameSchemas) check(t testing.TB, raw []byte) string {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("frame is not JSON: %v", err)
	}
	if err := f.envelope.Validate(doc); err != nil {
		t.Fatalf("frame does not validate against the envelope: %v\n%s", err, raw)
	}
	name, _ := doc.(map[string]any)["schema"].(string)
	sch, ok := f.byName[name]
	if !ok {
		t.Fatalf("frame with an unexpected schema %q", name)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("frame does not validate against %s: %v\n%s", name, err, raw)
	}
	return name
}
