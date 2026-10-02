package cis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
)

// Dataset is one of the CISP's datasets this system projects (spec 02
// F3; the DatasetPath enumeration of api/clients/cisp.yaml).
type Dataset string

// The three datasets of docs/PLAN.md section 5.1 cis_cache.
const (
	USpaceAirspace Dataset = "uspace_airspace"
	USSPList       Dataset = "ussp_list"
	Restrictions   Dataset = "restrictions"
)

// Datasets is every projected dataset, in a fixed order.
var Datasets = []Dataset{USpaceAirspace, USSPList, Restrictions}

// ParseDataset returns the projected dataset named s, or false.
func ParseDataset(s string) (Dataset, bool) {
	for _, d := range Datasets {
		if string(d) == s {
			return d, true
		}
	}
	return "", false
}

// ED318 reports whether d is an ED-318 FeatureCollection (ussp_list is
// the cis/ussp_list/v1 document).
func (d Dataset) ED318() bool { return d != USSPList }

// Bounds of one dataset read (E-10, brief WP-7).
const (
	// MaxDatasetBytes bounds a dataset answer once decoded (20 MB). The
	// same bound is ed318.Parse's MaxBytes, so a larger one is refused
	// before it is read whole.
	MaxDatasetBytes = 20 << 20
	// MaxFeatures bounds the features of one collection: a national
	// designation and its restrictions are tens to hundreds.
	MaxFeatures = 10_000
)

// ParseLimits are the limits a collection is parsed with: core's
// defaults (a zero field takes its DefaultLimits value) with MaxBytes
// raised to MaxDatasetBytes.
var ParseLimits = ed318.Limits{MaxBytes: MaxDatasetBytes}

// ussplistSchema is the schema of the ussp_list document.
const ussplistSchema = "cis/ussp_list/v1"

// Version is one accepted version of a dataset.
type Version struct {
	Dataset Dataset
	Number  int64
	ETag    string
	// Body is the bytes as served.
	Body []byte
	// UpdatedAt is the CISP's cis_updated_at (nil when absent).
	UpdatedAt *time.Time
	// Collection is the parsed ED-318 collection (nil for ussp_list).
	Collection *ed318.FeatureCollection
	// Volumes are the USPACE parts of uspace_airspace as uspace-core
	// zones (ed318.ToZones); nil for the other datasets.
	Volumes []*zones.Zone
	// USSPList is the parsed list (nil for the ED-318 datasets).
	USSPList *cispclient.UsspList
	// FetchedAt is when the CISP last confirmed this version, on the
	// database clock when there is a database.
	FetchedAt time.Time
}

// RefusalError is a dataset version refused whole (spec 06 T9): the
// first problem by JSON path and how many core listed. The version held
// before stays in use.
type RefusalError struct {
	Dataset  Dataset
	Version  int64
	First    string
	Problems int
}

func (r *RefusalError) Error() string {
	v := ""
	if r.Version > 0 {
		v = " version " + strconv.FormatInt(r.Version, 10)
	}
	return fmt.Sprintf("%s%s refused: %s (%d problems)", r.Dataset, v, r.First, r.Problems)
}

func refuse(d Dataset, version int64, first string) *RefusalError {
	return &RefusalError{Dataset: d, Version: version, First: first, Problems: 1}
}

// ParseVersion validates a dataset body as served and returns the
// version, or a *RefusalError. An ED-318 dataset goes through
// ed318.Parse with ParseLimits and is accepted whole or refused whole,
// never repaired; its top-level cis_dataset must name d and cis_version
// must be at least 1 and equal headerVersion (X-CIS-Version) when that
// is above 0. uspace_airspace must also build its zones with
// ed318.ToZones. ussp_list is decoded strictly into the generated
// cis/ussp_list/v1 type: an unknown member anywhere is refused.
func ParseVersion(d Dataset, body []byte, etag string, headerVersion int64) (*Version, *RefusalError) {
	if len(body) > MaxDatasetBytes {
		return nil, refuse(d, 0, fmt.Sprintf("body: longer than %d bytes", MaxDatasetBytes))
	}
	if d == USSPList {
		return parseUSSPList(body, etag, headerVersion)
	}
	fc, probs := ed318.Parse(body, ParseLimits)
	if probs != nil {
		r := &RefusalError{Dataset: d, Problems: len(probs.List) + probs.Truncated, First: "the collection does not parse"}
		if len(probs.List) > 0 {
			r.First = short(probs.List[0].Field + ": " + probs.List[0].Reason)
		}
		return nil, r
	}
	if n := len(fc.Features); n > MaxFeatures {
		return nil, refuse(d, 0, fmt.Sprintf("features: %d features, at most %d", n, MaxFeatures))
	}
	v := &Version{Dataset: d, ETag: etag, Body: body, Collection: fc}
	if rf := topLevel(d, fc.Extra, headerVersion, v); rf != nil {
		return nil, rf
	}
	if d == USpaceAirspace {
		zs, err := ed318.ToZones(fc, ed318.NOAADaylight{})
		if err != nil {
			return nil, refuse(d, v.Number, "zones: "+short(err.Error()))
		}
		v.Volumes = make([]*zones.Zone, 0, len(zs))
		for _, z := range zs {
			if z != nil && z.Type == core.ZoneUSpace {
				v.Volumes = append(v.Volumes, z)
			}
		}
	}
	return v, nil
}

// topLevel reads the CISP's cis_* members of a served collection into v.
func topLevel(d Dataset, extra map[string]json.RawMessage, headerVersion int64, v *Version) *RefusalError {
	var name string
	if err := json.Unmarshal(extra["cis_dataset"], &name); err != nil || name == "" {
		return refuse(d, 0, "cis_dataset: missing or not a string")
	}
	if name != string(d) {
		return refuse(d, 0, fmt.Sprintf("cis_dataset: %q is not %q", short(name), d))
	}
	if err := json.Unmarshal(extra["cis_version"], &v.Number); err != nil || v.Number < 1 {
		return refuse(d, 0, "cis_version: missing or not an integer of at least 1")
	}
	if headerVersion > 0 && headerVersion != v.Number {
		return refuse(d, v.Number, fmt.Sprintf("cis_version: %d is not X-CIS-Version %d", v.Number, headerVersion))
	}
	if raw, ok := extra["cis_updated_at"]; ok {
		var t time.Time
		if err := json.Unmarshal(raw, &t); err != nil {
			return refuse(d, v.Number, "cis_updated_at: not an RFC 3339 time")
		}
		t = t.UTC()
		v.UpdatedAt = &t
	}
	return nil
}

func parseUSSPList(body []byte, etag string, headerVersion int64) (*Version, *RefusalError) {
	var l cispclient.UsspList
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, refuse(USSPList, 0, "body: not a "+ussplistSchema+" document: "+short(err.Error()))
	}
	if dec.More() {
		return nil, refuse(USSPList, 0, "body: trailing data after the document")
	}
	switch {
	case string(l.Schema) != ussplistSchema:
		return nil, refuse(USSPList, 0, fmt.Sprintf("schema: %q is not %s", short(string(l.Schema)), ussplistSchema))
	case l.CisDataset == nil || string(*l.CisDataset) != string(USSPList):
		return nil, refuse(USSPList, 0, "cis_dataset: missing or not ussp_list")
	case l.CisVersion == nil || *l.CisVersion < 1:
		return nil, refuse(USSPList, 0, "cis_version: missing or not an integer of at least 1")
	case headerVersion > 0 && headerVersion != *l.CisVersion:
		return nil, refuse(USSPList, *l.CisVersion, fmt.Sprintf("cis_version: %d is not X-CIS-Version %d", *l.CisVersion, headerVersion))
	case l.Ussps == nil:
		return nil, refuse(USSPList, *l.CisVersion, "ussps: missing")
	case len(l.Ussps) > MaxUSSPs:
		return nil, refuse(USSPList, *l.CisVersion, fmt.Sprintf("ussps: %d entries, at most %d", len(l.Ussps), MaxUSSPs))
	}
	seen := make(map[string]bool, len(l.Ussps))
	for i := range l.Ussps {
		u := &l.Ussps[i]
		if u.UsspId == "" || seen[u.UsspId] {
			return nil, refuse(USSPList, *l.CisVersion, fmt.Sprintf("ussps[%d].ussp_id: empty or repeated", i))
		}
		seen[u.UsspId] = true
	}
	v := &Version{Dataset: USSPList, Number: *l.CisVersion, ETag: etag, Body: body, USSPList: &l}
	if l.CisUpdatedAt != nil {
		t := l.CisUpdatedAt.UTC()
		v.UpdatedAt = &t
	}
	return v, nil
}

// MaxUSSPs is the most entries of a ussp_list (the schema's maxItems).
const MaxUSSPs = 200

// short bounds an untrusted string quoted in a problem or a log line.
func short(s string) string {
	const maxRunes = 120
	if len(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "..."
}
