package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/sources"
)

type srcEntry struct{ v []byte }

func (e srcEntry) Bucket() string                  { return "source_control" }
func (e srcEntry) Key() string                     { return sources.KVKey }
func (e srcEntry) Value() []byte                   { return e.v }
func (e srcEntry) Revision() uint64                { return 1 }
func (e srcEntry) Created() time.Time              { return time.Time{} }
func (e srcEntry) Delta() uint64                   { return 0 }
func (e srcEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

type srcKV struct {
	mu   sync.Mutex
	v    []byte
	down bool
}

func (k *srcKV) Get(context.Context, string) (jetstream.KeyValueEntry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return nil, errors.New("kv down")
	}
	if k.v == nil {
		return nil, jetstream.ErrKeyNotFound
	}
	return srcEntry{v: k.v}, nil
}

func (k *srcKV) Create(_ context.Context, _ string, v []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.v = v
	return 1, nil
}

func (k *srcKV) Update(_ context.Context, _ string, v []byte, _ uint64) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.v = v
	return 2, nil
}

type srcRepo struct {
	mu   sync.Mutex
	rows []sources.Row
	err  error
}

func (r *srcRepo) Set(_ context.Context, c sources.Change) (sources.Row, sources.Doc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return sources.Row{}, sources.Doc{}, r.err
	}
	row := sources.Row{SourceType: c.SourceType, InstanceID: c.InstanceID, Enabled: c.Enabled, Reason: c.Reason, Actor: c.Actor,
		ChangedAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), Version: uint64(len(r.rows) + 1)}
	r.rows = append(r.rows, row)
	return row, sources.Doc{Version: row.Version, Epoch: "0d6c1f4e-3b2a-4c5d-8e9f-a0b1c2d3e4f5", Controls: r.rows}, nil
}

func (r *srcRepo) Load(context.Context) (sources.Doc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return sources.Doc{}, r.err
	}
	return sources.Doc{Version: uint64(len(r.rows)), Epoch: "0d6c1f4e-3b2a-4c5d-8e9f-a0b1c2d3e4f5", Controls: r.rows}, nil
}

func adminReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Session: true, Role: auth.RoleAdmin,
		Claims: coreauth.Claims{Subject: "admin-1"}}))
}

func TestSourceSwitchesThroughTheWriter(t *testing.T) {
	repo, kv := &srcRepo{}, &srcKV{}
	s := apiServer{src: &sourcesAPI{repo: repo, writer: &sources.Writer{Repo: repo, KV: kv}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rec := httptest.NewRecorder()
	s.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/adsb-tbs", `{"enabled":false,"reason":"maintenance"}`), gen.SetSourceControlParamsTypeManned, "adsb-tbs")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["instance_id"] != "adsb-tbs" || got["enabled"] != false || got["actor"] != "admin-1" || got["version"] != 1.0 {
		t.Fatalf("set %d %s", rec.Code, rec.Body)
	}
	if held, err := sources.DecodeDoc(kv.v); err != nil || len(held.Controls) != 1 {
		t.Fatalf("kv %s %v", kv.v, err)
	}
	rec = httptest.NewRecorder()
	s.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/*", `{"enabled":true,"reason":"type on"}`), gen.SetSourceControlParamsTypeManned, "*")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"instance_id":"*"`) {
		t.Fatalf("type %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.ListSources(rec, adminReq(http.MethodGet, "/v1/sources", ""))
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `"source_type":"manned"`) != 2 {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	// KV unreachable: 503 and nothing changed.
	kv.down = true
	rec = httptest.NewRecorder()
	s.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/adsb-tbs", `{"enabled":true,"reason":"back"}`), gen.SetSourceControlParamsTypeManned, "adsb-tbs")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || len(repo.rows) != 2 {
		t.Fatalf("kv down %d rows %d", rec.Code, len(repo.rows))
	}
	kv.down = false
	for name, body := range map[string]string{"no reason": `{"enabled":true}`, "blank reason": `{"enabled":true,"reason":" "}`, "unknown": `{"enabled":true,"reason":"r","x":1}`} {
		rec = httptest.NewRecorder()
		s.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/a", body), gen.SetSourceControlParamsTypeManned, "a")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	repo.err = errors.New("db down")
	rec = httptest.NewRecorder()
	s.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/a", `{"enabled":true,"reason":"r"}`), gen.SetSourceControlParamsTypeManned, "a")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("db down %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.ListSources(rec, adminReq(http.MethodGet, "/v1/sources", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("list db down %d", rec.Code)
	}
	// No relational database: 503.
	none := apiServer{}
	rec = httptest.NewRecorder()
	none.ListSources(rec, adminReq(http.MethodGet, "/v1/sources", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no db %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	none.SetSourceControl(rec, adminReq(http.MethodPut, "/v1/sources/manned/a", `{}`), gen.SetSourceControlParamsTypeManned, "a")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no db set %d", rec.Code)
	}
	// A machine token is not an admin.
	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/v1/sources/manned/a", strings.NewReader(`{"enabled":true,"reason":"r"}`))
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Claims: coreauth.Claims{Subject: "ussp-01"}}))
	s.SetSourceControl(rec, r, gen.SetSourceControlParamsTypeManned, "a")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("machine %d", rec.Code)
	}
}
