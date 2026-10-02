package restriction

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// memRepo is Repo and Tx in memory: a transaction works on a copy and
// is kept only when fn returns nil. Area and placement are measured with
// core's planar containment (enough for the fixtures; the store measures
// on geography).
type memRepo struct {
	mu       sync.Mutex
	now      time.Time
	pol      policy.Policy
	rs       map[string]Restriction
	versions map[string][]Version
	bus      map[string]int64
	reqs     map[string]Request
	events   []audit.Event
	idem     map[string][2]string
	seq      int64
	areaM2   float64
	failNow  error
	failLock error
	seqMax   int64
	// fail makes the named Tx method fail (error-path tests).
	fail map[string]error
}

func (m *memRepo) failing(name string) error { return m.fail[name] }

func newMemRepo(now time.Time) *memRepo {
	pol := policy.Policy{Version: 7, Thresholds: policy.Defaults()}
	return &memRepo{now: now, pol: pol, rs: map[string]Restriction{}, versions: map[string][]Version{}, bus: map[string]int64{},
		reqs: map[string]Request{}, idem: map[string][2]string{}, areaM2: 1e6, seqMax: IdentifierSpace}
}

func (m *memRepo) advance(d time.Duration) {
	m.mu.Lock()
	m.now = m.now.Add(d)
	m.mu.Unlock()
}

type memTx struct{ m *memRepo }

func (m *memRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs, vs, bus, reqs, ev, idem, seq := maps.Clone(m.rs), map[string][]Version{}, maps.Clone(m.bus), maps.Clone(m.reqs), slices.Clone(m.events), maps.Clone(m.idem), m.seq
	for k, v := range m.versions {
		vs[k] = slices.Clone(v)
	}
	if err := fn(ctx, memTx{m}); err != nil {
		m.rs, m.versions, m.bus, m.reqs, m.events, m.idem, m.seq = rs, vs, bus, reqs, ev, idem, seq
		return err
	}
	return nil
}

func (m *memRepo) current(r Restriction) Restriction {
	vs := m.versions[r.ID]
	if len(vs) > 0 {
		v := vs[len(vs)-1]
		r.Feature, r.Constraint = v.Feature, v.Constraint
	}
	return r
}

func (m *memRepo) Get(_ context.Context, id string) (Restriction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rs[id]
	if !ok {
		return Restriction{}, ErrNotFound
	}
	return m.current(r), nil
}

func (m *memRepo) List(_ context.Context, f ListFilter) ([]Restriction, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Restriction
	for id := range m.rs {
		r := m.rs[id]
		if f.State != nil && r.State != *f.State {
			continue
		}
		if f.At != nil && (f.At.Before(r.StartsAt) || !f.At.Before(r.EndsAt)) {
			continue
		}
		out = append(out, m.current(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	more := len(out) > f.Limit
	if more {
		out = out[:f.Limit]
	}
	return out, more, nil
}

func (m *memRepo) Versions(_ context.Context, id string, limit int) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vs := m.versions[id]
	if len(vs) > limit {
		vs = vs[:limit]
	}
	return slices.Clone(vs), nil
}

func (m *memRepo) Version(_ context.Context, id string, version int64) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.versions[id] {
		if v := m.versions[id][i]; v.Version == version {
			return v, nil
		}
	}
	return Version{}, ErrNotFound
}

func (m *memRepo) Request(_ context.Context, id string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q, ok := m.reqs[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	return q, nil
}

func (m *memRepo) DueActivations(_ context.Context, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id := range m.rs {
		r := m.rs[id]
		if r.State == StatePlanned && r.ActivateAt != nil && !r.ActivateAt.After(m.now) && len(out) < limit {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memRepo) DueExpiries(_ context.Context, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id := range m.rs {
		r := m.rs[id]
		if r.State == StateActive && !r.EndsAt.After(m.now) && len(out) < limit {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memRepo) Unpublished(_ context.Context, limit int) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Version
	ids := slices.Sorted(maps.Keys(m.versions))
	for _, id := range ids {
		for i := range m.versions[id] {
			if v := m.versions[id][i]; v.Version > m.bus[id] && len(out) < limit {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (m *memRepo) MarkPublished(_ context.Context, id string, version int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bus[id] = max(m.bus[id], version)
	return nil
}

func (t memTx) Now(context.Context) (time.Time, error) {
	if t.m.failNow != nil {
		return time.Time{}, t.m.failNow
	}
	return t.m.now, nil
}

func (t memTx) Policy(context.Context) (policy.Policy, error) {
	if err := t.m.failing("Policy"); err != nil {
		return policy.Policy{}, err
	}
	return t.m.pol, nil
}

func (t memTx) MintIdentifier(context.Context) (string, error) {
	if err := t.m.failing("MintIdentifier"); err != nil {
		return "", err
	}
	if t.m.seq >= t.m.seqMax {
		return "", &Refusal{Status: 503, Slug: SlugIdentifiersSpent, Detail: "spent"}
	}
	n := t.m.seq
	t.m.seq++
	return Identifier(n, 12345)
}

func (t memTx) ByIdempotency(_ context.Context, actorID, key string) (string, string, bool, error) {
	if err := t.m.failing("ByIdempotency"); err != nil {
		return "", "", false, err
	}
	v, ok := t.m.idem[actorID+"/"+key]
	return v[0], v[1], ok, nil
}

func (t memTx) Insert(_ context.Context, r Restriction, idem *Idempotency) error {
	if err := t.m.failing("Insert"); err != nil {
		return err
	}
	if _, dup := t.m.rs[r.ID]; dup {
		return ErrConflict
	}
	r.Feature, r.Constraint = nil, nil
	t.m.rs[r.ID] = r
	if idem != nil {
		t.m.idem[idem.ActorID+"/"+idem.Key] = [2]string{r.ID, idem.SHA256}
	}
	return nil
}

func (t memTx) Lock(_ context.Context, id string) (Restriction, error) {
	if t.m.failLock != nil {
		return Restriction{}, t.m.failLock
	}
	r, ok := t.m.rs[id]
	if !ok {
		return Restriction{}, ErrNotFound
	}
	return t.m.current(r), nil
}

func (t memTx) Update(_ context.Context, prev int64, r Restriction) error {
	if err := t.m.failing("Update"); err != nil {
		return err
	}
	cur, ok := t.m.rs[r.ID]
	if !ok || cur.AnspVersion != prev {
		return ErrConflict
	}
	r.Feature, r.Constraint = nil, nil
	t.m.rs[r.ID] = r
	return nil
}

func (t memTx) InsertVersion(_ context.Context, v Version) error {
	if err := t.m.failing("InsertVersion"); err != nil {
		return err
	}
	vs := t.m.versions[v.RestrictionID]
	if len(vs) > 0 && vs[len(vs)-1].Version >= v.Version {
		return errors.New("version does not rise")
	}
	t.m.versions[v.RestrictionID] = append(vs, v)
	return nil
}

func (t memTx) Audit(_ context.Context, ev audit.Event) error {
	if err := t.m.failing("Audit"); err != nil {
		return err
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	if _, err := json.Marshal(ev.Payload); err != nil {
		return err
	}
	t.m.events = append(t.m.events, ev)
	return nil
}

func (t memTx) Successor(_ context.Context, id string) (string, bool, error) {
	if err := t.m.failing("Successor"); err != nil {
		return "", false, err
	}
	for sid := range t.m.rs {
		r := t.m.rs[sid]
		if r.SupersedesID != nil && *r.SupersedesID == id && r.State == StatePlanned {
			return sid, true, nil
		}
	}
	return "", false, nil
}

func (t memTx) AreaM2(context.Context, Shape) (float64, error) {
	if err := t.m.failing("AreaM2"); err != nil {
		return 0, err
	}
	return t.m.areaM2, nil
}

// Relate: planar containment of the shape's vertices (a circle by its
// bounding box corners) in a polygon part.
func (t memTx) Relate(_ context.Context, s Shape, p Part) (Relation, error) {
	if err := t.m.failing("Relate"); err != nil {
		return Relation{}, err
	}
	var g struct {
		Coordinates [][][2]float64 `json:"coordinates"`
	}
	if err := json.Unmarshal([]byte(p.GeoJSON), &g); err != nil || len(g.Coordinates) == 0 {
		return Relation{}, errors.New("fake measures polygon parts only")
	}
	poly := geodesy.Polygon{Rings: []geodesy.Ring{geodesy.RingFromLonLat(g.Coordinates[0])}}
	pts := s.Ring
	if s.IsCircle() {
		b := geodesy.Circle{Center: *s.Center, RadiusM: s.RadiusM}.BBox()
		pts = []core.LatLon{{LatDeg: b.MinLat, LonDeg: b.MinLon}, {LatDeg: b.MaxLat, LonDeg: b.MaxLon}, {LatDeg: b.MinLat, LonDeg: b.MaxLon}, {LatDeg: b.MaxLat, LonDeg: b.MinLon}}
	}
	in := 0
	for _, pt := range pts {
		if poly.Contains(pt) {
			in++
		}
	}
	return Relation{Intersects: in > 0, Covers: in == len(pts)}, nil
}

func (t memTx) RequestByClientRef(_ context.Context, requester, ref string) (Request, bool, error) {
	if err := t.m.failing("RequestByClientRef"); err != nil {
		return Request{}, false, err
	}
	for id := range t.m.reqs {
		q := t.m.reqs[id]
		if q.Requester == requester && q.ClientRef == ref {
			return q, true, nil
		}
	}
	return Request{}, false, nil
}

func (t memTx) CountOpenRequests(_ context.Context, requester string) (int64, error) {
	if err := t.m.failing("CountOpenRequests"); err != nil {
		return 0, err
	}
	var n int64
	for id := range t.m.reqs {
		q := t.m.reqs[id]
		if q.Requester == requester && q.State == RequestReceived {
			n++
		}
	}
	return n, nil
}

func (t memTx) InsertRequest(_ context.Context, q Request) error {
	if err := t.m.failing("InsertRequest"); err != nil {
		return err
	}
	t.m.reqs[q.ID] = q
	return nil
}

func (t memTx) LockRequest(_ context.Context, id string) (Request, error) {
	if err := t.m.failing("LockRequest"); err != nil {
		return Request{}, err
	}
	q, ok := t.m.reqs[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	return q, nil
}

func (t memTx) DecideRequest(_ context.Context, q Request) error {
	if err := t.m.failing("DecideRequest"); err != nil {
		return err
	}
	cur, ok := t.m.reqs[q.ID]
	if !ok || cur.State != RequestReceived {
		return ErrConflict
	}
	t.m.reqs[q.ID] = q
	return nil
}

// memBus records what is published; fail makes it refuse.
type memBus struct {
	mu   sync.Mutex
	msgs []published
	fail bool
}

type published struct {
	subject, id string
	data        []byte
}

func (b *memBus) Publish(_ context.Context, subject, id string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("bus down")
	}
	b.msgs = append(b.msgs, published{subject, id, data})
	return nil
}

func (b *memBus) subjects() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.msgs))
	for _, m := range b.msgs {
		out = append(out, m.subject[:strings.LastIndexByte(m.subject, '.')])
	}
	return out
}

// staticAirspaces is a fixed CIS snapshot.
type staticAirspaces struct {
	snap Snapshot
	err  error
}

func (a staticAirspaces) Current(context.Context) (Snapshot, error) { return a.snap, a.err }

// gridGeoid is a fixture undulation that varies across longitude: N =
// 10 + 2 * (lon - 44) metres.
type gridGeoid struct{ fail bool }

func (g gridGeoid) UndulationM(p core.LatLon) (float64, error) {
	if g.fail {
		return 0, errors.New("outside the grid")
	}
	return 10 + 2*(p.LonDeg-44), nil
}

// uspaceFeature is a fixture USPACE feature: a box 44.6..45.0 E,
// 41.6..41.9 N up to upper metres in ref.
func uspaceFeature(id string, upper float64, ref core.VerticalRef) ed318.Feature {
	u, l := upper, 0.0
	name := "U-space " + id
	return ed318.Feature{
		Type: "Feature",
		Geometry: ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{{
			{LatDeg: 41.6, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 44.6},
		}}, Layer: &ed318.Layer{Upper: &u, UpperReference: ref, Lower: &l, LowerReference: ref}},
		Properties: ed318.UASZone{Identifier: id, Country: "GEO", Type: core.ZoneUSpace, Name: []ed318.Text{{Text: &name, Lang: "en"}}},
	}
}
