package coord

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const examples = "../../schemas/examples/coordination/annex_v/v1"

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examples, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noticeMap is the nonconformance example as a map, to break one member
// at a time.
func noticeMap(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readExample(t, "nonconformance.json"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intentOf(m map[string]any) map[string]any {
	return m["intents"].([]any)[0].(map[string]any)
}

func volumeOf(m map[string]any) map[string]any {
	return intentOf(m)["volumes"].([]any)[0].(map[string]any)
}

// Every valid example of the schema is accepted, and every invalid one
// is refused naming its member (presence and absence, E-01).
func TestDecodeNoticeExamples(t *testing.T) {
	entries, err := os.ReadDir(examples)
	if err != nil {
		t.Fatal(err)
	}
	valid := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d, errs := DecodeNotice(readExample(t, e.Name()))
		if len(errs) > 0 {
			t.Errorf("%s: refused %v", e.Name(), errs)
			continue
		}
		if !d.Kind.Valid() || d.NoticeRef == "" || len(d.Intents) == 0 || len(d.SHA256) != 32 || len(d.Boxes()) == 0 {
			t.Errorf("%s: %+v", e.Name(), d)
		}
		valid++
	}
	if valid < 4 {
		t.Fatalf("%d valid examples", valid)
	}
	for name, field := range map[string]string{
		"f3548-state-ended.json":             "intents[0].state",
		"no-intents.json":                    "intents",
		"nonconformance-without-detail.json": "nonconformance",
		"unknown-kind.json":                  "kind",
		"volume-altitude-amsl.json":          "intents[0].volumes[0].volume.altitude_lower.reference",
		"wrong-schema-name.json":             "schema",
	} {
		_, errs := DecodeNotice(readExample(t, filepath.Join("invalid", name)))
		if len(errs) == 0 || errs[0].Field != field {
			t.Errorf("%s: %v, want the first error on %s", name, errs, field)
		}
	}
}

func TestDecodeNoticeAcceptsAnUnknownMember(t *testing.T) {
	m := noticeMap(t)
	m["future_member"] = map[string]any{"x": 1}
	intentOf(m)["future_member"] = true
	d, errs := DecodeNotice(encode(t, m))
	if len(errs) > 0 || d.Kind != KindNonconformance {
		t.Fatal(errs)
	}
	// The stored body keeps it (nothing is repaired or dropped).
	if !strings.Contains(string(d.Raw), "future_member") {
		t.Fatal("the unknown member was dropped")
	}
}

func TestDecodeNoticeRefusesKindOutsideTheEnum(t *testing.T) {
	m := noticeMap(t)
	m["kind"] = "chatter"
	_, errs := DecodeNotice(encode(t, m))
	if len(errs) == 0 || errs[0].Field != "kind" {
		t.Fatal(errs)
	}
}

// E-10: the bounds are refused, and just inside them accepted.
func TestDecodeNoticeBounds(t *testing.T) {
	m := noticeMap(t)
	in := intentOf(m)
	many := make([]any, 1000)
	for i := range many {
		many[i] = in
	}
	m["intents"] = many
	if _, errs := DecodeNotice(encode(t, m)); len(errs) != 1 || errs[0].Field != "intents" || !strings.Contains(errs[0].Reason, "at most 100") {
		t.Fatalf("1000 intents: %v", errs)
	}
	m["intents"] = many[:MaxIntents]
	if _, errs := DecodeNotice(encode(t, m)); len(errs) > 0 {
		t.Fatalf("100 intents: %v", errs)
	}
	big := make([]byte, MaxNoticeBytes+1)
	if _, errs := DecodeNotice(big); len(errs) != 1 || errs[0].Field != "body" {
		t.Fatal(errs)
	}
	m = noticeMap(t)
	vols := make([]any, MaxVolumes+1)
	for i := range vols {
		vols[i] = volumeOf(m)
	}
	intentOf(m)["volumes"] = vols
	if _, errs := DecodeNotice(encode(t, m)); len(errs) != 1 || errs[0].Field != "intents[0].volumes" {
		t.Fatal(errs)
	}
	// Many broken members: the list stops at maxFieldErrors.
	m = noticeMap(t)
	bad := make([]any, MaxIntents)
	for i := range bad {
		bad[i] = map[string]any{"intent_ref": 1, "authorisation_number": 2, "state": 3, "time_start": 4, "time_end": 5, "volumes": 6}
	}
	m["intents"] = bad
	if _, errs := DecodeNotice(encode(t, m)); len(errs) != maxFieldErrors {
		t.Fatalf("%d errors", len(errs))
	}
}

func TestDecodeNoticeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(m map[string]any)
		field  string
	}{
		"schema missing":         {func(m map[string]any) { delete(m, "schema") }, "schema"},
		"schema not a string":    {func(m map[string]any) { m["schema"] = 1 }, "schema"},
		"notice_ref empty":       {func(m map[string]any) { m["notice_ref"] = "" }, "notice_ref"},
		"notice_ref too long":    {func(m map[string]any) { m["notice_ref"] = strings.Repeat("x", 129) }, "notice_ref"},
		"ussp_id null":           {func(m map[string]any) { m["ussp_id"] = nil }, "ussp_id"},
		"sent_at not a time":     {func(m map[string]any) { m["sent_at"] = "yesterday" }, "sent_at"},
		"sent_at a number":       {func(m map[string]any) { m["sent_at"] = 1 }, "sent_at"},
		"intents not an array":   {func(m map[string]any) { m["intents"] = "x" }, "intents"},
		"intents missing":        {func(m map[string]any) { delete(m, "intents") }, "intents"},
		"intent not an object":   {func(m map[string]any) { m["intents"] = []any{1} }, "intents[0]"},
		"intent_ref not a UUID":  {func(m map[string]any) { intentOf(m)["intent_ref"] = "not-a-uuid" }, "intents[0].intent_ref"},
		"intent_ref UUID braces": {func(m map[string]any) { intentOf(m)["intent_ref"] = "{6d1c2b4e-9a0f-4e3b-8c7d-2a1b0c9d8e7f}" }, "intents[0].intent_ref"},
		"authorisation missing":  {func(m map[string]any) { delete(intentOf(m), "authorisation_number") }, "intents[0].authorisation_number"},
		"times out of order":     {func(m map[string]any) { intentOf(m)["time_end"] = "2026-10-02T12:00:00.000Z" }, "intents[0].time_end"},
		"time_start missing":     {func(m map[string]any) { delete(intentOf(m), "time_start") }, "intents[0].time_start"},
		"volumes missing":        {func(m map[string]any) { delete(intentOf(m), "volumes") }, "intents[0].volumes"},
		"volumes empty":          {func(m map[string]any) { intentOf(m)["volumes"] = []any{} }, "intents[0].volumes"},
		"volumes not an array":   {func(m map[string]any) { intentOf(m)["volumes"] = 1 }, "intents[0].volumes"},
		"volume wrong type":      {func(m map[string]any) { intentOf(m)["volumes"] = []any{map[string]any{"volume": 1}} }, "intents[0].volumes[0]"},
		"volume without outline": {func(m map[string]any) { delete(volumeOf(m)["volume"].(map[string]any), "outline_polygon") }, "intents[0].volumes[0].volume"},
		"altitudes upside down": {func(m map[string]any) {
			volumeOf(m)["volume"].(map[string]any)["altitude_lower"].(map[string]any)["value"] = 5000
		}, "intents[0].volumes[0].volume.altitude_upper"},
		"altitude units feet": {func(m map[string]any) {
			volumeOf(m)["volume"].(map[string]any)["altitude_upper"].(map[string]any)["units"] = "FT"
		}, "intents[0].volumes[0].volume.altitude_upper.units"},
		"nonconformance missing":  {func(m map[string]any) { delete(m, "nonconformance") }, "nonconformance"},
		"nonconformance a string": {func(m map[string]any) { m["nonconformance"] = "x" }, "nonconformance"},
		"nc intent_ref":           {func(m map[string]any) { m["nonconformance"].(map[string]any)["intent_ref"] = "x" }, "nonconformance.intent_ref"},
		"nc reason":               {func(m map[string]any) { m["nonconformance"].(map[string]any)["reason"] = "bored" }, "nonconformance.reason"},
		"nc detected_at":          {func(m map[string]any) { delete(m["nonconformance"].(map[string]any), "detected_at") }, "nonconformance.detected_at"},
		"nc distance negative":    {func(m map[string]any) { m["nonconformance"].(map[string]any)["distance_outside_m"] = -1 }, "nonconformance.distance_outside_m"},
		"nc position": {func(m map[string]any) {
			m["nonconformance"].(map[string]any)["position"] = map[string]any{"lat": 95, "lng": 0}
		}, "nonconformance.position"},
		"nc altitude a string": {func(m map[string]any) { m["nonconformance"].(map[string]any)["alt_wgs84_m"] = "high" }, "nonconformance.alt_wgs84_m"},
		"remarks long":         {func(m map[string]any) { m["remarks"] = strings.Repeat("r", MaxRemarksBytes+1) }, "remarks"},
		"remarks a number":     {func(m map[string]any) { m["remarks"] = 1 }, "remarks"},
		"nonconformance on intent": {func(m map[string]any) {
			m["kind"] = "intent_notice"
			m["nonconformance"].(map[string]any)["reason"] = "bored"
		}, "nonconformance.reason"},
	} {
		t.Run(name, func(t *testing.T) {
			m := noticeMap(t)
			tc.mutate(m)
			d, errs := DecodeNotice(encode(t, m))
			if len(errs) == 0 || errs[0].Field != tc.field {
				t.Fatalf("%v, want the first error on %s", errs, tc.field)
			}
			if d.NoticeRef != "" || d.Raw != nil {
				t.Fatal("a refused notice returned members")
			}
		})
	}
}

func TestDecodeNoticeRefusesWhatIsNotOneObject(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "{", `{"a":1} {"b":2}`, "\xff\xfe", `"x"`} {
		if _, errs := DecodeNotice([]byte(body)); len(errs) != 1 || errs[0].Field != "body" {
			t.Errorf("%q: %v", body, errs)
		}
	}
}

// The canonical hash ignores layout and member order and tells another
// body apart.
func TestCanonicalHash(t *testing.T) {
	a, _ := DecodeNotice(readExample(t, "nonconformance.json"))
	m := noticeMap(t)
	b, _ := DecodeNotice(encode(t, m))
	if !bytes.Equal(a.SHA256, b.SHA256) {
		t.Fatal("the same notice re-encoded hashes differently")
	}
	m["remarks"] = "another notice"
	c, _ := DecodeNotice(encode(t, m))
	if bytes.Equal(a.SHA256, c.SHA256) {
		t.Fatal("another body hashes the same")
	}
}

func TestIntentRefsAndBoxes(t *testing.T) {
	m := noticeMap(t)
	in := intentOf(m)
	m["intents"] = []any{in, in}
	d, errs := DecodeNotice(encode(t, m))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if len(d.IntentRefs()) != 1 || len(d.AuthorisationNumbers()) != 1 {
		t.Fatalf("%v %v", d.IntentRefs(), d.AuthorisationNumbers())
	}
	bx := d.Boxes()
	if len(bx) != 2 || bx[0].MinLon > 44.78 || bx[0].MaxLon < 44.82 || bx[0].MinLat > 41.7 || bx[0].MaxLat < 41.73 {
		t.Fatalf("%+v", bx)
	}
	// A volume without times takes its intent's window.
	delete(volumeOf(m), "time_start")
	delete(volumeOf(m), "time_end")
	d, _ = DecodeNotice(encode(t, m))
	if got := d.Boxes()[0]; !got.TStart.Equal(d.Intents[0].TimeStart) || !got.TEnd.Equal(d.Intents[0].TimeEnd) {
		t.Fatalf("%+v", got)
	}
	// A volume across the antimeridian is two boxes.
	volumeOf(m)["volume"].(map[string]any)["outline_polygon"] = map[string]any{"vertices": []any{
		map[string]any{"lat": -17.0, "lng": 179.9}, map[string]any{"lat": -17.0, "lng": -179.9}, map[string]any{"lat": -16.9, "lng": -179.9},
	}}
	intentOf(m)["volumes"] = []any{volumeOf(m)}
	m["intents"] = []any{intentOf(m)}
	d, errs = DecodeNotice(encode(t, m))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if bx := d.Boxes(); len(bx) != 2 || bx[0].MaxLon != 180 || bx[1].MinLon != -180 {
		t.Fatalf("%+v", bx)
	}
}

func TestKindsAndStates(t *testing.T) {
	for _, k := range Kinds {
		if !k.Valid() {
			t.Fatal(k)
		}
	}
	if Kind("x").Valid() || !KindNonconformance.AckRequired() || !KindContingent.AckRequired() || KindIntentNotice.AckRequired() || KindEnded.AckRequired() {
		t.Fatal("kinds")
	}
	at := time.Now()
	if (Notice{}).State() != StateReceived || (Notice{EscalatedAt: &at}).State() != StateEscalated ||
		(Notice{Acknowledged: true, EscalatedAt: &at}).State() != StateAcknowledged || State("lost").Valid() || !StateEscalated.Valid() {
		t.Fatal("states")
	}
}

func TestClipText(t *testing.T) {
	if got := clipText("ab\xffcd", 10); got != "ab?cd" {
		t.Fatal(got)
	}
	if got := clipText(strings.Repeat("é", 10), 5); got != "éé..." {
		t.Fatal(got)
	}
}
