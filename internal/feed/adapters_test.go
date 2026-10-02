package feed

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAdaptersRemembersTheLastStatus(t *testing.T) {
	a := NewAdapters()
	if !a.Silent(t0, 15) {
		t.Fatal("no adapter heard is silent")
	}
	if !a.Observe("adsb-tbs", statusMsg("adsb-tbs", AdapterLive, true, t0), t0) {
		t.Fatal("refused a good status")
	}
	a.Observe("adsb-kut", statusMsg("adsb-kut", AdapterDisabled, false, t0), t0)
	st := a.States(t0.Add(2*time.Second), 15)
	if len(st) != 2 || st[0].ID != "adsb-kut" || st[0].State != AdapterDisabled || st[0].Enabled || st[1].State != AdapterLive ||
		st[1].AgeS == nil || *st[1].AgeS != 2 {
		t.Fatalf("states %+v", st)
	}
	if a.Silent(t0.Add(2*time.Second), 15) {
		t.Fatal("silent with a live adapter")
	}
	// The adapter process went quiet: its last status is older than the
	// liveness bound, so it is down whatever that status said.
	if st := a.States(t0.Add(16*time.Second), 15); st[1].State != AdapterDown {
		t.Fatalf("not down: %+v", st[1])
	}
	if !a.Silent(t0.Add(16*time.Second), 15) {
		t.Fatal("not silent")
	}
	src := a.Sources()
	if len(src) != 2 || !strings.Contains(string(src[0]), `"source_instance":"adsb-kut"`) {
		t.Fatalf("sources %s", src)
	}
}

func TestAdaptersRefusesWhatIsNotAStatusOfThatAdapter(t *testing.T) {
	a := NewAdapters()
	good := string(statusMsg("adsb-tbs", AdapterLive, true, t0))
	for name, c := range map[string]struct{ subject, msg string }{
		"other adapter": {"adsb-kut", good},
		"bad subject":   {"Bad Subject", good},
		"schema":        {"adsb-tbs", strings.Replace(good, "source/status/v1", "source/status/v2", 1)},
		"state":         {"adsb-tbs", strings.Replace(good, `"state":"live"`, `"state":"fine"`, 1)},
		"source":        {"adsb-tbs", strings.Replace(good, `"source":"ansp_feed"`, `"source":"sitl"`, 1)},
		"counters":      {"adsb-tbs", strings.Replace(good, `"counters":{"accepted":10,"refused":0}`, `"counters":{}`, 1)},
		"not json":      {"adsb-tbs", `{`},
		"long":          {"adsb-tbs", good + strings.Repeat(" ", MaxMessageBytes)},
	} {
		if a.Observe(c.subject, []byte(c.msg), t0) {
			t.Errorf("%s accepted", name)
		}
	}
	if a.Counters().Get(CounterStatusRefused) != 8 {
		t.Fatalf("refused %d", a.Counters().Get(CounterStatusRefused))
	}
}

func TestAdaptersAreBounded(t *testing.T) {
	a := NewAdapters()
	for i := 0; i < MaxAdapters; i++ {
		id := fmt.Sprintf("a%d", i)
		if !a.Observe(id, statusMsg(id, AdapterLive, true, t0), t0) {
			t.Fatalf("refused %s", id)
		}
	}
	if a.Observe("one-more", statusMsg("one-more", AdapterLive, true, t0), t0) || a.Counters().Get(CounterStatusFull) != 1 {
		t.Fatal("past the bound")
	}
	// A known adapter is still updated at the bound.
	if !a.Observe("a0", statusMsg("a0", AdapterStale, true, t0), t0) {
		t.Fatal("a known adapter refused at the bound")
	}
}
