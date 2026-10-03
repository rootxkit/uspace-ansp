package dss

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// store is a fake Store.
type store struct {
	w         Written
	err       error
	retention time.Duration
}

func (s *store) Written(_ context.Context, _ string, retention time.Duration) (Written, error) {
	s.retention = retention
	return s.w, s.err
}

func written(t testing.TB, vols []f3548.Volume4D) Written {
	ovn := "ovn-7"
	typ := "DAR"
	ref, err := json.Marshal(f3548.ConstraintReference{Id: testID, Manager: "ansp-01", Ovn: &ovn, Version: 2, UssAvailability: "Unknown",
		UssBaseUrl: "https://ansp.test", TimeStart: *vols[0].TimeStart, TimeEnd: *vols[0].TimeEnd})
	if err != nil {
		t.Fatal(err)
	}
	det, err := json.Marshal(f3548.ConstraintDetails{Volumes: vols, Type: &typ})
	if err != nil {
		t.Fatal(err)
	}
	return Written{Reference: ref, Details: det}
}

// A USSP reads exactly the volumes that were written (the restriction's
// F3548 volumes), type DAR, and the reference with its ovn; an unknown
// constraint and one past the retention are ErrUnknown (404), each
// counted; a stored document that cannot be read is an error, never an
// empty 200.
func TestDetails(t *testing.T) {
	s := &store{w: written(t, volumes())}
	c := &core.Counters{}
	d := &Details{Store: s, Counters: c}
	body, err := d.Get(context.Background(), testID)
	if err != nil {
		t.Fatal(err)
	}
	if s.retention != 24*time.Hour {
		t.Fatalf("retention %v (ExternalDataMaxRetentionTimeHours)", s.retention)
	}
	var resp f3548.GetConstraintDetailsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Constraint.Details.Volumes, volumes()) || *resp.Constraint.Details.Type != "DAR" ||
		*resp.Constraint.Reference.Ovn != "ovn-7" || resp.Constraint.Reference.Id != testID {
		t.Fatalf("%s", body)
	}
	if c.Get(CounterDetailsServed) != 1 {
		t.Fatal("not counted")
	}
	s.w.Expired = true
	if _, err := d.Get(context.Background(), testID); !errors.Is(err, ErrUnknown) || c.Get(CounterDetailsExpired) != 1 {
		t.Fatalf("expired: %v", err)
	}
	s.err = ErrUnknown
	if _, err := d.Get(context.Background(), testID); !errors.Is(err, ErrUnknown) || c.Get(CounterDetailsUnknown) != 1 {
		t.Fatalf("unknown: %v", err)
	}
	s.err = errors.New("db down")
	if _, err := d.Get(context.Background(), testID); err == nil || errors.Is(err, ErrUnknown) {
		t.Fatalf("store failure: %v", err)
	}
	for name, w := range map[string]Written{
		"reference": {Reference: json.RawMessage(`[]`), Details: written(t, volumes()).Details},
		"details":   {Reference: written(t, volumes()).Reference, Details: json.RawMessage(`[]`)},
		"no volume": {Reference: written(t, volumes()).Reference, Details: json.RawMessage(`{"volumes":[]}`)},
	} {
		s.err, s.w = nil, w
		if _, err := d.Get(context.Background(), testID); err == nil || errors.Is(err, ErrUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c.Get(CounterDetailsUnusable) != 3 {
		t.Fatal("unusable not counted")
	}
	d.Retention = time.Hour
	_, _ = d.Get(context.Background(), testID)
	if s.retention != time.Hour {
		t.Fatal("the configured retention")
	}
}

// BenchmarkConstraintDetails: the handler's work for a restriction of
// CstrMaxVertices vertices (the largest it can hold), from the stored
// documents to the response body (budget: 200 ms p99 with the query,
// docs/PLAN.md section 9).
func BenchmarkConstraintDetails(b *testing.B) {
	vols := volumes()
	poly := make([]f3548.LatLngPoint, 0, f3548.CstrMaxVertices)
	for i := range f3548.CstrMaxVertices {
		a := 2 * math.Pi * float64(i) / f3548.CstrMaxVertices
		poly = append(poly, f3548.LatLngPoint{Lat: 41.7 + 0.05*math.Sin(a), Lng: 44.8 + 0.05*math.Cos(a)})
	}
	vols[0].Volume.OutlinePolygon.Vertices = poly
	d := &Details{Store: &store{w: written(b, vols)}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := d.Get(context.Background(), testID); err != nil {
			b.Fatal(err)
		}
	}
}
