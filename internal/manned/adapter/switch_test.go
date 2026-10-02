package adapter_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

func doc(t *testing.T, d adapter.ControlDoc) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ptr(s string) *string { return &s }

// Before any state the switch is enabled and unknown (B-09: never fail
// closed); the KV read with no key makes it known.
func TestKVSwitchUnknownThenKnown(t *testing.T) {
	sw := adapter.NewKVSwitch("adsb-tbs", nil)
	if d := sw.Decide(); !d.Enabled || d.Known {
		t.Fatalf("%+v", d)
	}
	sw.MarkKnown()
	if d := sw.Decide(); !d.Enabled || !d.Known {
		t.Fatalf("%+v", d)
	}
}

// Off by instance, by type and by default deny, each with the deciding
// row's actor and reason; on again with a higher version (E-01).
func TestKVSwitchDecisions(t *testing.T) {
	sw := adapter.NewKVSwitch("adsb-tbs", nil)
	instOff := adapter.ControlDoc{Version: 1, Epoch: "e1", Controls: []adapter.ControlRow{
		{SourceType: "manned", InstanceID: ptr("adsb-tbs"), Enabled: false, Actor: "admin-1", Reason: "receiver maintenance"},
		{SourceType: "manned", InstanceID: ptr("other"), Enabled: true, Actor: "admin-2", Reason: "x"},
	}}
	if !sw.ApplyJSON(doc(t, instOff)) {
		t.Fatal("not applied")
	}
	d := sw.Decide()
	if d.Enabled || *d.Why != sources.WhyInstance || d.Actor != "admin-1" || d.Reason != "receiver maintenance" || !d.Known {
		t.Fatalf("%+v", d)
	}
	typeOff := adapter.ControlDoc{Version: 2, Epoch: "e1", Controls: []adapter.ControlRow{
		{SourceType: "manned", Enabled: false, Actor: "supervisor", Reason: "feed suspect"},
		{SourceType: "manned", InstanceID: ptr("adsb-tbs"), Enabled: true, Actor: "admin-1", Reason: "back"},
	}}
	sw.ApplyJSON(doc(t, typeOff))
	if d := sw.Decide(); d.Enabled || *d.Why != sources.WhyType || d.Actor != "supervisor" {
		t.Fatalf("%+v", d)
	}
	sw.ApplyJSON(doc(t, adapter.ControlDoc{Version: 3, Epoch: "e1", DefaultDeny: true}))
	if d := sw.Decide(); d.Enabled || *d.Why != sources.WhyDefaultDeny || d.Actor != "default_deny" {
		t.Fatalf("%+v", d)
	}
	sw.ApplyJSON(doc(t, adapter.ControlDoc{Version: 4, Epoch: "e1"}))
	if d := sw.Decide(); !d.Enabled || d.Why != nil {
		t.Fatalf("%+v", d)
	}
}

// An older version is ignored, a new epoch is taken; an undecodable or
// oversized document is refused and counted.
func TestKVSwitchOrderAndRefusals(t *testing.T) {
	sw := adapter.NewKVSwitch("adsb-tbs", nil)
	sw.ApplyJSON(doc(t, adapter.ControlDoc{Version: 5, Epoch: "e1"}))
	stale := adapter.ControlDoc{Version: 4, Epoch: "e1", Controls: []adapter.ControlRow{{SourceType: "manned", Enabled: false}}}
	if sw.ApplyJSON(doc(t, stale)) || !sw.Decide().Enabled {
		t.Fatal("an older version was applied")
	}
	restored := stale
	restored.Epoch = "e2"
	if !sw.ApplyJSON(doc(t, restored)) || sw.Decide().Enabled {
		t.Fatal("a new epoch was not applied")
	}
	for _, bad := range [][]byte{
		[]byte(`{"version":1}`),
		[]byte(`{"version":9,"epoch":"e2","unknown":1}`),
		[]byte(`not json`),
		[]byte(`{"version":9,"epoch":"e2","controls":[` + strings.Repeat(`{"source_type":"manned","enabled":true},`, 8000) + `{}]}`),
	} {
		if sw.ApplyJSON(bad) {
			t.Fatalf("applied %.40s", bad)
		}
	}
}
