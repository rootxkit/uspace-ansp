package cis_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// Presence: every fixture parses as the CISP serves it, with its
// version, its U-space volume and its USSPs.
func TestFixturesParse(t *testing.T) {
	want := map[cis.Dataset]int64{cis.USpaceAirspace: 3, cis.USSPList: 2, cis.Restrictions: 7}
	for _, d := range cis.Datasets {
		v, rf := cis.ParseVersion(d, fixture(t, d, 0), `"e"`, want[d])
		if rf != nil {
			t.Fatalf("%s: %v", d, rf)
		}
		if v.Number != want[d] || v.UpdatedAt == nil || v.ETag != `"e"` {
			t.Fatalf("%s: %+v", d, v)
		}
	}
	v, _ := cis.ParseVersion(cis.USpaceAirspace, fixture(t, cis.USpaceAirspace, 0), "", 0)
	if len(v.Volumes) != 1 || v.Volumes[0].Identifier != "TSTU01" || v.Volumes[0].Type != core.ZoneUSpace || v.Volumes[0].Upper == nil {
		t.Fatalf("volumes: %+v", v.Volumes)
	}
	if ext := v.Collection.Features[0].Properties.ExtendedProperties; ext["uspace_requirements"] == nil {
		t.Fatalf("the Art. 3(4) block is not carried: %v", ext)
	}
	l, _ := cis.ParseVersion(cis.USSPList, fixture(t, cis.USSPList, 0), "", 0)
	if len(l.USSPList.Ussps) != 2 || !strings.HasPrefix(l.USSPList.Ussps[0].BaseUrl, "https://localhost:") {
		t.Fatalf("ussps: %+v", l.USSPList.Ussps)
	}
}

// Absence: a dataset with any problem is refused whole, never repaired,
// and says its first problem.
func TestParseRefusals(t *testing.T) {
	ua := fixture(t, cis.USpaceAirspace, 0)
	ul := fixture(t, cis.USSPList, 0)
	set := func(b []byte, member, raw string) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if raw == "" {
			delete(m, member)
		} else {
			m[member] = json.RawMessage(raw)
		}
		out, _ := json.Marshal(m)
		return out
	}
	for _, tc := range []struct {
		name  string
		d     cis.Dataset
		body  []byte
		hdr   int64
		first string
	}{
		{"not json", cis.USpaceAirspace, []byte("{"), 0, ""},
		{"a feature without a vertical reference", cis.USpaceAirspace, bytes.Replace(ua, []byte(`"upperReference": "AMSL", `), nil, 1), 0, "features[0]"},
		{"no cis_dataset", cis.USpaceAirspace, set(ua, "cis_dataset", ""), 0, "cis_dataset"},
		{"another dataset", cis.USpaceAirspace, ua, 0, "cis_dataset"}, // parsed as restrictions below
		{"no cis_version", cis.USpaceAirspace, set(ua, "cis_version", ""), 0, "cis_version"},
		{"cis_version zero", cis.USpaceAirspace, set(ua, "cis_version", "0"), 0, "cis_version"},
		{"header version differs", cis.USpaceAirspace, ua, 4, "X-CIS-Version"},
		{"bad cis_updated_at", cis.USpaceAirspace, set(ua, "cis_updated_at", `"yesterday"`), 0, "cis_updated_at"},
		{"ussp_list unknown member", cis.USSPList, set(ul, "extra", `1`), 0, "body"},
		{"ussp_list wrong schema", cis.USSPList, set(ul, "schema", `"cis/ussp_list/v2"`), 0, "schema"},
		{"ussp_list no cis_dataset", cis.USSPList, set(ul, "cis_dataset", ""), 0, "cis_dataset"},
		{"ussp_list no cis_version", cis.USSPList, set(ul, "cis_version", ""), 0, "cis_version"},
		{"ussp_list header version differs", cis.USSPList, ul, 9, "X-CIS-Version"},
		{"ussp_list no ussps", cis.USSPList, set(ul, "ussps", ""), 0, "ussps"},
		{"ussp_list trailing data", cis.USSPList, append(append([]byte{}, ul...), []byte(" {}")...), 0, "trailing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.d
			if tc.name == "another dataset" {
				d = cis.Restrictions
			}
			v, rf := cis.ParseVersion(d, tc.body, "", tc.hdr)
			if rf == nil || v != nil {
				t.Fatalf("accepted: %+v", v)
			}
			if !strings.Contains(rf.Error(), tc.first) || rf.Problems < 1 {
				t.Fatalf("problem %q, want %q", rf.Error(), tc.first)
			}
		})
	}
}

// A repeated ussp_id is refused (the list keys the USSPs by it).
func TestUSSPListRepeatedID(t *testing.T) {
	b := bytes.Replace(fixture(t, cis.USSPList, 0), []byte(`"GEO-TEST-U2"`), []byte(`"GEO-TEST-U1"`), 1)
	if _, rf := cis.ParseVersion(cis.USSPList, b, "", 0); rf == nil || !strings.Contains(rf.First, "ussp_id") {
		t.Fatalf("repeated id: %v", rf)
	}
}

// E-10: a body past 20 MB is refused before it is parsed; one at the
// bound is parsed (and refused only for what it says).
func TestParseBodyBound(t *testing.T) {
	big := make([]byte, cis.MaxDatasetBytes+1)
	if _, rf := cis.ParseVersion(cis.USpaceAirspace, big, "", 0); rf == nil || !strings.Contains(rf.First, "longer than") {
		t.Fatalf("21 MB: %v", rf)
	}
	if _, rf := cis.ParseVersion(cis.USSPList, big, "", 0); rf == nil || !strings.Contains(rf.First, "longer than") {
		t.Fatalf("21 MB list: %v", rf)
	}
}

// E-10: 10 001 features are refused by the feature bound; 10 000 are
// taken.
func TestParseFeatureBound(t *testing.T) {
	build := func(n int) []byte {
		var b bytes.Buffer
		b.WriteString(`{"type":"FeatureCollection","features":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"type":"Feature","geometry":{"type":"Point","coordinates":[44.7,41.7],"extent":{"subType":"Circle","radius":100},"layer":{"upper":100,"upperReference":"AMSL","lower":0,"lowerReference":"AMSL"}},"properties":{"identifier":"R%05d","country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR"],"zoneAuthority":[{"name":[{"text":"t","lang":"en"}],"purpose":"AUTHORIZATION","email":"a@example.invalid"}]}}`, i)
		}
		b.WriteString(`],"cis_dataset":"restrictions","cis_version":1}`)
		return b.Bytes()
	}
	if _, rf := cis.ParseVersion(cis.Restrictions, build(cis.MaxFeatures+1), "", 0); rf == nil || !strings.Contains(rf.First, "features") {
		t.Fatalf("10 001 features: %v", rf)
	}
	v, rf := cis.ParseVersion(cis.Restrictions, build(cis.MaxFeatures), "", 0)
	if rf != nil || len(v.Collection.Features) != cis.MaxFeatures {
		t.Fatalf("10 000 features: %v", rf)
	}
}

func TestParseDataset(t *testing.T) {
	for _, d := range cis.Datasets {
		if got, ok := cis.ParseDataset(string(d)); !ok || got != d {
			t.Fatalf("%s", d)
		}
	}
	if _, ok := cis.ParseDataset("zones"); ok {
		t.Fatal("zones is not projected here")
	}
	if !cis.USpaceAirspace.ED318() || cis.USSPList.ED318() {
		t.Fatal("ED318")
	}
	if cis.PublisherOf(cis.Restrictions) != cis.PublisherANSP || cis.PublisherOf(cis.USSPList) != cis.PublisherAuthority {
		t.Fatal("publishers")
	}
}
