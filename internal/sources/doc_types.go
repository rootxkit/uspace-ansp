package sources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
)

// KVKey is the key of the state in the bucket source_control.
const KVKey = "current"

// SourceTypeManned is the source type of every surveillance adapter.
const SourceTypeManned = "manned"

// Bounds of a document (E-10).
const (
	MaxDocBytes   = 256 << 10
	MaxRows       = 1000
	MaxReasonLen  = 500
	MaxActorLen   = 256
	MaxEpochBytes = 64
)

var (
	sourceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	instancePattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Row is one switch: a whole source type when InstanceID is nil, one
// instance of it otherwise (a row of source_controls).
type Row struct {
	SourceType string    `json:"source_type"`
	InstanceID *string   `json:"instance_id"`
	Enabled    bool      `json:"enabled"`
	Reason     string    `json:"reason"`
	Actor      string    `json:"actor"`
	ChangedAt  time.Time `json:"changed_at"`
	// Version is the row's own version (source_controls.version), for
	// GET /v1/sources; the document carries only the highest, so it is
	// not on the wire of KV and ctl.sources.
	Version uint64 `json:"-"`
}

// Doc is the source-control state as it travels on KV and ctl.sources.
type Doc struct {
	Version     uint64 `json:"version"`
	Epoch       string `json:"epoch"`
	DefaultDeny bool   `json:"default_deny"`
	Controls    []Row  `json:"controls"`
}

// ValidSourceType reports whether t is a source type as source_controls
// stores it.
func ValidSourceType(t string) bool { return sourceTypePattern.MatchString(t) }

// ValidInstance reports whether id is an instance id as source_controls
// stores it.
func ValidInstance(id string) bool { return instancePattern.MatchString(id) }

// Validate refuses a document a follower must not apply, naming the
// member at fault.
func (d *Doc) Validate() error {
	var errs []error
	if d.Epoch == "" || len(d.Epoch) > MaxEpochBytes {
		errs = append(errs, core.Fieldf("epoch", "required, at most %d bytes", MaxEpochBytes))
	}
	if len(d.Controls) > MaxRows {
		errs = append(errs, core.Fieldf("controls", "more than %d rows", MaxRows))
		return errors.Join(errs...)
	}
	for i := range d.Controls {
		r := &d.Controls[i]
		at := fmt.Sprintf("controls[%d]", i)
		if !ValidSourceType(r.SourceType) {
			errs = append(errs, core.Fieldf(at+".source_type", "not a source type"))
		}
		if r.InstanceID != nil && !ValidInstance(*r.InstanceID) {
			errs = append(errs, core.Fieldf(at+".instance_id", "not an instance id"))
		}
		if len(r.Reason) > MaxReasonLen {
			errs = append(errs, core.Fieldf(at+".reason", "longer than %d bytes", MaxReasonLen))
		}
		if len(r.Actor) > MaxActorLen {
			errs = append(errs, core.Fieldf(at+".actor", "longer than %d bytes", MaxActorLen))
		}
	}
	return errors.Join(errs...)
}

// DecodeDoc decodes a KV value or a ctl.sources push strictly: bounded,
// unknown members refused, Validate applied.
func DecodeDoc(b []byte) (Doc, error) {
	if len(b) > MaxDocBytes {
		return Doc{}, core.Fieldf("document", "longer than %d bytes", MaxDocBytes)
	}
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Doc{}, core.Fieldf("document", "not a source-control document")
	}
	if dec.More() {
		return Doc{}, core.Fieldf("document", "trailing data")
	}
	if err := d.Validate(); err != nil {
		return Doc{}, err
	}
	return d, nil
}

// Encode is the document's bytes, as written to KV and ctl.sources.
func (d *Doc) Encode() ([]byte, error) {
	if d.Controls == nil {
		d.Controls = []Row{}
	}
	return json.Marshal(d)
}

// State is the document as uspace-core judges it.
func (d *Doc) State() coresources.State {
	st := coresources.State{DefaultDeny: d.DefaultDeny, Version: d.Version, Epoch: d.Epoch}
	st.Controls = make([]coresources.Control, 0, len(d.Controls))
	for _, r := range d.Controls {
		st.Controls = append(st.Controls, coresources.Control{SourceType: r.SourceType, InstanceID: r.InstanceID, Enabled: r.Enabled})
	}
	return st
}

// newer reports whether d moves past cur as core's follower would take
// it: a first state, a higher version within the epoch, or a new epoch.
func newer(d, cur *Doc) bool {
	return cur == nil || d.Epoch != cur.Epoch || d.Version > cur.Version
}
