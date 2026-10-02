package restriction

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Every op from every state: the legal ones change what they say and
// bump the version; every other is a *TransitionError naming both.
func TestTransitionTable(t *testing.T) {
	legal := map[State]map[Op]State{
		StatePlanned: {OpActivate: StateActive, OpCancel: StateCancelled},
		StateActive:  {OpExtend: StateActive, OpEnd: StateEnded, OpExpire: StateEnded},
	}
	ops := []Op{OpPlan, OpActivate, OpExtend, OpEnd, OpCancel, OpExpire}
	for _, from := range []State{StatePlanned, StateActive, StateEnded, StateCancelled} {
		for _, op := range ops {
			r := sample()
			r.State = from
			now := r.StartsAt.Add(time.Hour)
			if op == OpExpire {
				now = r.EndsAt
			}
			end := r.EndsAt.Add(time.Hour)
			ch, err := Transition(r, op, now, supervisor, &end)
			want, ok := legal[from][op]
			if !ok {
				var te *TransitionError
				if !errors.As(err, &te) || te.From != from || te.Op != op || !strings.Contains(te.Error(), string(from)) {
					t.Fatalf("%s from %s: %v", op, from, err)
				}
				continue
			}
			if err != nil || !ch.Versioned || ch.Next.State != want || ch.Next.AnspVersion != r.AnspVersion+1 {
				t.Fatalf("%s from %s: %+v %v", op, from, ch, err)
			}
		}
	}
}

func TestTransitionDetails(t *testing.T) {
	r := sample()
	// Activate before starts_at: scheduled, unversioned.
	ch, err := Transition(r, OpActivate, r.StartsAt.Add(-time.Minute), supervisor, nil)
	if err != nil || ch.Versioned || ch.Next.State != StatePlanned || !ch.Next.ActivateAt.Equal(r.StartsAt) {
		t.Fatalf("%+v %v", ch, err)
	}
	// Activate after the window: refused with the reason.
	_, err = Transition(r, OpActivate, r.EndsAt, supervisor, nil)
	var te *TransitionError
	if !errors.As(err, &te) || !strings.Contains(te.Error(), "window ended") {
		t.Fatal(err)
	}
	// End sets ends_at to now; expire keeps it and is refused early.
	a := r
	a.State = StateActive
	now := r.StartsAt.Add(time.Hour)
	if ch, _ := Transition(a, OpEnd, now, supervisor, nil); !ch.Next.EndsAt.Equal(now) || !ch.Next.EndedAtActual.Equal(now) {
		t.Fatalf("%+v", ch.Next)
	}
	if _, err := Transition(a, OpExpire, now, SystemActor, nil); err == nil || !strings.Contains(err.Error(), "never before") {
		t.Fatal(err)
	}
	// Extend needs a later end, after now, within 24 h of starts_at.
	for _, end := range []*time.Time{nil, ptr(a.EndsAt), ptr(now.Add(-time.Minute)), ptr(a.StartsAt.Add(25 * time.Hour))} {
		if _, err := Transition(a, OpExtend, now, supervisor, end); err == nil {
			t.Fatalf("extend to %v accepted", end)
		}
	}
	if !NeedsReissue(a, now, a.StartsAt.Add(25*time.Hour)) || NeedsReissue(a, now, a.StartsAt.Add(5*time.Hour)) {
		t.Fatal("NeedsReissue")
	}
	if (&TransitionError{Op: OpPlan, From: StatePlanned}).Error() == "" || allowedFrom(Op("x")) != "never" {
		t.Fatal("plan is never a transition")
	}
	if State("x").Valid() || !StateEnded.Terminal() || StateActive.Terminal() || OpEnd.EventType() != "restriction_end" {
		t.Fatal("state helpers")
	}
}

// compileSchema compiles schemas/<name>.json with every schema of this
// repository added by $id, offline (as schemas/schemas_test.go does).
func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	root := filepath.Join("..", "..", "schemas")
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
	s, err := c.Compile("https://schemas.uspace.ge/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// What goes on restr.v1 is a valid restriction/state/v1 in its envelope
// (the schema this repo owns), for every state; a broken one is refused
// (the absence pair: the validator does refuse).
func TestStateMessageValidates(t *testing.T) {
	sch := compileSchema(t, "restriction/state/v1")
	f, _ := Feature(sample(), cfg)
	raw, _ := CheckFeature(f)
	for _, st := range []State{StatePlanned, StateActive, StateEnded, StateCancelled} {
		v := Version{RestrictionID: sample().ID, AnspRef: sample().AnspRef, Version: 2, State: st, StartsAt: t0, EndsAt: t0.Add(time.Hour),
			MsgID: NewULID(t0), Feature: raw, ChangedAt: t0.Add(time.Second)}
		msg, err := StateMessage(v, "ansp/api", st == StateEnded)
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(msg))
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("%s: %v\n%s", st, err, msg)
		}
		if Subject(v) != "restr.v1."+string(st)+"."+v.RestrictionID || DedupeID(v) != v.RestrictionID+".2" {
			t.Fatal(Subject(v), DedupeID(v))
		}
	}
	v := Version{RestrictionID: sample().ID, AnspRef: sample().AnspRef, Version: 0, State: StateActive, MsgID: NewULID(t0), Feature: raw}
	msg, _ := StateMessage(v, "ansp/api", false)
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(msg))
	if sch.Validate(doc) == nil {
		t.Fatal("ansp_version 0 validated")
	}
	if _, err := StateMessage(Version{}, "ansp/api", false); err == nil {
		t.Fatal("an empty version")
	}
	var env Envelope
	_ = json.Unmarshal(msg, &env)
	if env.Schema != SchemaState || env.TimeSource != TimeSourceSystem {
		t.Fatalf("%+v", env)
	}
}
