package coord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// SchemaOccurrence is the authority's occurrence message (04 section
// 3.3; the authority owns it, M14). Until the authority's OpenAPI
// publishes it (docs/PLAN.md section 15 row 23) the body is the 04
// section 3.3 field list, OccurrenceMessage.
const SchemaOccurrence = "occurrence/v1"

// Bounds of an occurrence report (E-10), the OccurrenceCreate schema's.
const (
	MaxOccurrenceBytes   = 256 << 10
	MaxOccurrenceItems   = 50
	MaxNarrativeBytes    = 10000
	MaxPersonRefBytes    = 128
	maxOccurrenceTextLen = 128
)

// Counters of the occurrence outbox.
const (
	CounterOccurrencesQueued    = "occurrences_queued"
	CounterOccurrencesRefused   = "occurrences_refused"
	CounterOccurrenceAlarms     = "occurrences_undelivered_alarms"
	CounterOccurrenceCleared    = "occurrences_undelivered_cleared"
	CounterOccurrenceSendFailed = "occurrences_send_prepare_failed"
)

// OpReport is the op of an occurrence job.
const OpReport = "report"

var (
	occurrenceChannels   = []string{"mandatory", "voluntary"}
	occurrenceCategories = []string{"airprox", "nonconformance_in_prohibited", "lost_link_in_uspace", "emergency", "other"}
	icao24Pattern        = regexp.MustCompile(`^[0-9a-f]{6}$`)
)

// Aircraft is one UAS of a report (04 section 3.3).
type Aircraft struct {
	Serial              string `json:"serial,omitempty"`
	OperatorReg         string `json:"operator_reg,omitempty"`
	FlightID            string `json:"flight_id,omitempty"`
	AuthorisationNumber string `json:"authorisation_number,omitempty"`
}

// Manned is one manned aircraft of a report.
type Manned struct {
	ICAO24   string `json:"icao24,omitempty"`
	Callsign string `json:"callsign,omitempty"`
}

// Separation is the minimum separation of a report.
type Separation struct {
	HM *float64 `json:"h_m,omitempty"`
	VM *float64 `json:"v_m,omitempty"`
	At *string  `json:"at,omitempty"`
}

// OccurrenceInput is a report as a supervisor entered it, checked.
// PersonRef is the reporter's opaque reference: sealed at rest, sent to
// the authority in clear over TLS (M13), never logged, streamed or
// exported.
type OccurrenceInput struct {
	Channel       string
	OccurredAt    time.Time
	BecameAwareAt time.Time
	Category      string
	Aircraft      []Aircraft
	Manned        []Manned
	IntentRefs    []string
	MinSeparation *Separation
	Narrative     string
	PersonRef     string `json:"-"`
}

// DecodeOccurrence reads an OccurrenceCreate body member by member.
// Unknown members are ignored (02 section 1).
func DecodeOccurrence(body []byte) (OccurrenceInput, []*core.FieldError) {
	var e errs
	if len(body) > MaxOccurrenceBytes {
		e.add("body", "is %d bytes; at most %d", len(body), MaxOccurrenceBytes)
		return OccurrenceInput{}, e.list
	}
	var top map[string]json.RawMessage
	if !utf8.Valid(body) || strictObject(body, &top) != nil {
		e.add("body", "is not one JSON object")
		return OccurrenceInput{}, e.list
	}
	var in OccurrenceInput
	if ch, ok := str(&e, top, "channel", 16); ok {
		if !contains(occurrenceChannels, ch) {
			e.add("channel", "is not mandatory or voluntary")
		}
		in.Channel = ch
	}
	if c, ok := str(&e, top, "category", 64); ok {
		if !contains(occurrenceCategories, c) {
			e.add("category", "is not airprox, nonconformance_in_prohibited, lost_link_in_uspace, emergency or other")
		}
		in.Category = c
	}
	occ, okO := timestamp(&e, top, "occurred_at", "occurred_at", true)
	aware, okA := timestamp(&e, top, "became_aware_at", "became_aware_at", true)
	if okO && okA && aware.Before(occ) {
		e.add("became_aware_at", "is before occurred_at")
	}
	in.OccurredAt, in.BecameAwareAt = occ, aware
	in.Narrative, _ = str(&e, top, "narrative", MaxNarrativeBytes)
	if raw, ok := top["reporter_person_ref"]; ok && !isNull(raw) {
		var s string
		if json.Unmarshal(raw, &s) != nil || len(s) > MaxPersonRefBytes {
			// The reason never echoes the value (it is a person's reference).
			e.add("reporter_person_ref", "must be a string of at most %d bytes", MaxPersonRefBytes)
		} else {
			in.PersonRef = strings.TrimSpace(s)
		}
	}
	list(&e, top["aircraft"], "aircraft", func(path string, raw json.RawMessage) {
		var a Aircraft
		if json.Unmarshal(raw, &a) != nil {
			e.add(path, "must be an object of strings {serial, operator_reg, flight_id, authorisation_number}")
			return
		}
		for name, v := range map[string]string{"serial": a.Serial, "operator_reg": a.OperatorReg, "flight_id": a.FlightID, "authorisation_number": a.AuthorisationNumber} {
			if len(v) > maxOccurrenceTextLen {
				e.add(path+"."+name, "is longer than %d bytes", maxOccurrenceTextLen)
			}
		}
		in.Aircraft = append(in.Aircraft, a)
	})
	list(&e, top["manned"], "manned", func(path string, raw json.RawMessage) {
		var m Manned
		if json.Unmarshal(raw, &m) != nil {
			e.add(path, "must be an object {icao24, callsign}")
			return
		}
		if m.ICAO24 != "" && !icao24Pattern.MatchString(m.ICAO24) {
			e.add(path+".icao24", "is not six lower-case hexadecimal digits")
		}
		if len(m.Callsign) > maxOccurrenceTextLen {
			e.add(path+".callsign", "is longer than %d bytes", maxOccurrenceTextLen)
		}
		in.Manned = append(in.Manned, m)
	})
	list(&e, top["intent_refs"], "intent_refs", func(path string, raw json.RawMessage) {
		var s string
		if json.Unmarshal(raw, &s) != nil || !isUUID(s) {
			e.add(path, "is not a UUID")
			return
		}
		in.IntentRefs = append(in.IntentRefs, strings.ToLower(s))
	})
	if raw, ok := top["min_separation"]; ok && !isNull(raw) {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			e.add("min_separation", "must be an object {h_m, v_m, at}")
		} else {
			sep := &Separation{}
			for name, dst := range map[string]**float64{"h_m": &sep.HM, "v_m": &sep.VM} {
				if r, ok := obj[name]; ok && !isNull(r) {
					var v float64
					if json.Unmarshal(r, &v) != nil || !core.IsFinite(v) || v < 0 {
						e.add("min_separation."+name, "must be a number of metres, at least 0")
						continue
					}
					*dst = &v
				}
			}
			if at, ok := timestamp(&e, obj, "at", "min_separation.at", false); ok {
				s := restriction.Stamp(at)
				sep.At = &s
			}
			in.MinSeparation = sep
		}
	}
	if len(e.list) > 0 {
		return OccurrenceInput{}, e.list
	}
	return in, nil
}

// list reads an optional array of at most MaxOccurrenceItems items.
func list(e *errs, raw json.RawMessage, path string, item func(path string, raw json.RawMessage)) {
	if raw == nil || isNull(raw) {
		return
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		e.add(path, "must be an array")
		return
	}
	if len(items) > MaxOccurrenceItems {
		e.add(path, "has %d items; at most %d", len(items), MaxOccurrenceItems)
		return
	}
	for i, r := range items {
		item(fmt.Sprintf("%s[%d]", path, i), r)
	}
}

// Sealer seals the reporter's reference at rest (internal/auth Sealer on
// ANSP_SECRETS_KEY_FILE).
type Sealer interface {
	KeyID() string
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(keyID string, sealed, aad []byte) ([]byte, error)
}

// Occurrences is the occurrence outbox: a report is stored with its
// reporter reference sealed, queued to the authority in the same
// transaction, sent by the outbox worker, and alarmed when it is not
// delivered OccurrenceAlarmAfter after its reporter became aware.
type Occurrences struct {
	Repo   Repo
	Sealer Sealer
	Outbox *deliver.Outbox
	// Authority posts to the authority (nil: every attempt fails,
	// retried and alarmed).
	Authority *deliver.Authority
	// Org is the reporter's organisation in the report (this system's
	// client id).
	Org    string
	Policy Policy
	// Clock is now for the alarm; nil is the database clock.
	Clock Clock

	counters core.Counters
}

// Counters are the occurrence outbox's counters.
func (o *Occurrences) Counters() *core.Counters { return &o.counters }

func (o *Occurrences) now(ctx context.Context) (time.Time, error) {
	if o.Clock != nil {
		return o.Clock(ctx)
	}
	return o.Repo.Now(ctx)
}

// Queued is a stored report as the API answers it.
type Queued struct {
	ID         string `json:"id"`
	ReportRef  string `json:"report_ref"`
	State      string `json:"state"`
	DeadlineAt string `json:"deadline_at"`
}

// Create stores the report of actor, sealed, with its delivery job and
// audit event in one transaction, then publishes the job. A reporter
// reference without a secrets key is refused 503: it is never stored in
// clear.
func (o *Occurrences) Create(ctx context.Context, actor Actor, in OccurrenceInput) (Queued, error) {
	if in.PersonRef != "" && o.Sealer == nil {
		o.counters.Inc(CounterOccurrencesRefused)
		return Queued{}, &Refusal{Status: http.StatusServiceUnavailable, Slug: "secrets_key_unavailable", RetryAfter: 60 * time.Second,
			Detail: "the reporter reference cannot be sealed: ANSP_SECRETS_KEY_FILE is not set on this instance"}
	}
	if o.Outbox == nil {
		o.counters.Inc(CounterOccurrencesRefused)
		return Queued{}, &Refusal{Status: http.StatusServiceUnavailable, Slug: "outbox_unavailable", RetryAfter: 60 * time.Second,
			Detail: "the outbox is not run on this instance"}
	}
	aircraft, _ := json.Marshal(nonNilSlice(in.Aircraft))
	manned, _ := json.Marshal(nonNilSlice(in.Manned))
	var sep json.RawMessage
	if in.MinSeparation != nil {
		sep, _ = json.Marshal(in.MinSeparation)
	}
	var out Occurrence
	err := o.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		dtx := tx.Outbox()
		now, err := dtx.Now(ctx)
		if err != nil {
			return err
		}
		ref, err := tx.NextOccurrenceRef(ctx)
		if err != nil {
			return err
		}
		id, deliveryID := restriction.NewULID(now), restriction.NewULID(now)
		window := max(in.BecameAwareAt.Add(OccurrenceDeadline).Sub(now), o.Outbox.Policy.Window)
		if _, _, err := o.Outbox.Enqueue(ctx, dtx, deliver.Job{ID: deliveryID, Kind: deliver.KindOccurrence, Op: OpReport,
			Target: deliver.TargetAuthority, Subject: id, Key: ref, Window: window}); err != nil {
			return err
		}
		rec := NewOccurrence{ID: id, ReportRef: ref, Channel: in.Channel, OccurredAt: in.OccurredAt, BecameAwareAt: in.BecameAwareAt,
			Category: in.Category, Aircraft: aircraft, Manned: manned, IntentRefs: in.IntentRefs, MinSeparation: sep,
			Narrative: in.Narrative, CreatedBy: actor.ID, DeliveryID: deliveryID}
		if in.PersonRef != "" {
			if rec.PersonRefSealed, err = o.Sealer.Seal([]byte(in.PersonRef), []byte(id)); err != nil {
				return err
			}
			rec.KeyID = o.Sealer.KeyID()
		}
		if out, err = tx.InsertOccurrence(ctx, rec); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: actor.ID,
			Purpose:    "occurrence report queued to the authority (376/2014 Art. 4(8))",
			EntityType: "occurrence_report", EntityID: id, EventType: "occurrence_report_queued",
			Payload: map[string]any{"report_ref": ref, "channel": in.Channel, "category": in.Category, "role": actor.Role,
				"deadline_at": restriction.Stamp(out.DeadlineAt), "delivery_id": deliveryID, "has_reporter_ref": in.PersonRef != ""}})
	})
	if err != nil {
		return Queued{}, err
	}
	o.counters.Inc(CounterOccurrencesQueued)
	o.Outbox.PublishAll(ctx, []deliver.Pending{{ID: out.DeliveryID, Kind: deliver.KindOccurrence}})
	return Queued{ID: out.ID, ReportRef: out.ReportRef, State: "queued", DeadlineAt: restriction.Stamp(out.DeadlineAt)}, nil
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Reporter is the reporter of an occurrence message.
type Reporter struct {
	Org       string `json:"org"`
	PersonRef string `json:"person_ref,omitempty"`
}

// OccurrenceMessage is the occurrence/v1 body sent to the authority:
// the 04 section 3.3 field list until the authority publishes its
// schema (docs/PLAN.md section 15 row 23). It is built at each attempt
// and never stored, logged, streamed or exported (it holds the person
// reference in clear).
type OccurrenceMessage struct {
	Schema        string          `json:"schema"`
	ReportRef     string          `json:"report_ref"`
	Channel       string          `json:"channel"`
	OccurredAt    string          `json:"occurred_at"`
	BecameAwareAt string          `json:"became_aware_at"`
	Category      string          `json:"category"`
	Reporter      Reporter        `json:"reporter"`
	Aircraft      json.RawMessage `json:"aircraft"`
	Manned        json.RawMessage `json:"manned"`
	IntentRefs    []string        `json:"intent_refs"`
	MinSeparation json.RawMessage `json:"min_separation,omitempty"`
	Narrative     string          `json:"narrative"`
	EvidenceURLs  []string        `json:"evidence_urls"`
	ReportedAt    string          `json:"reported_at"`
}

// redacted stands for the reporter's reference in what the authority
// answered, should it echo it.
const redacted = "[reporter reference]"

// SendOccurrence is one attempt of an occurrence job: the report read
// by its delivery, the reporter reference opened, the occurrence/v1 body
// posted to the authority. The reference never leaves in the answer's
// excerpt or error.
func (o *Occurrences) SendOccurrence(ctx context.Context, d deliver.Delivery) deliver.Response {
	rec, err := o.Repo.OccurrenceByDelivery(ctx, d.ID)
	if err != nil {
		o.counters.Inc(CounterOccurrenceSendFailed)
		return deliver.Response{Err: "the report cannot be read"}
	}
	person := ""
	if len(rec.PersonRefSealed) > 0 {
		if o.Sealer == nil {
			o.counters.Inc(CounterOccurrenceSendFailed)
			return deliver.Response{Err: "the reporter reference cannot be opened: ANSP_SECRETS_KEY_FILE is not set"}
		}
		p, err := o.Sealer.Open(rec.KeyID, rec.PersonRefSealed, []byte(rec.ID))
		if err != nil {
			o.counters.Inc(CounterOccurrenceSendFailed)
			return deliver.Response{Err: "the reporter reference does not open under the configured key"}
		}
		person = string(p)
	}
	body, err := json.Marshal(MessageOf(rec, o.Org, person))
	if err != nil {
		return deliver.Response{Err: "the report cannot be encoded"}
	}
	if o.Authority == nil {
		return deliver.Response{Err: "no authority configured (ANSP_AUTHORITY_URL)"}
	}
	resp := o.Authority.Post(ctx, deliver.PathOccurrences, body)
	if person != "" {
		resp.Excerpt = strings.ReplaceAll(resp.Excerpt, person, redacted)
		resp.Err = strings.ReplaceAll(resp.Err, person, redacted)
	}
	return resp
}

// MessageOf is the occurrence/v1 body of rec with the opened reporter
// reference.
func MessageOf(rec Occurrence, org, person string) OccurrenceMessage {
	refs := rec.IntentRefs
	if refs == nil {
		refs = []string{}
	}
	m := OccurrenceMessage{Schema: SchemaOccurrence, ReportRef: rec.ReportRef, Channel: rec.Channel,
		OccurredAt: restriction.Stamp(rec.OccurredAt), BecameAwareAt: restriction.Stamp(rec.BecameAwareAt), Category: rec.Category,
		Reporter: Reporter{Org: org, PersonRef: person}, Aircraft: rawOr(rec.Aircraft), Manned: rawOr(rec.Manned), IntentRefs: refs,
		Narrative: rec.Narrative, EvidenceURLs: []string{}, ReportedAt: restriction.Stamp(rec.CreatedAt)}
	if len(rec.MinSeparation) > 0 && json.Valid(rec.MinSeparation) {
		m.MinSeparation = rec.MinSeparation
	}
	return m
}

func rawOr(r json.RawMessage) json.RawMessage {
	if len(r) == 0 || !json.Valid(r) {
		return json.RawMessage("[]")
	}
	return r
}

// MonitorReport is what one pass of the occurrence monitor did.
type MonitorReport struct {
	Raised  []deliver.Alarm
	Cleared []deliver.Alarm
}

// Monitor raises occurrence_undelivered for every report not delivered
// OccurrenceAlarmAfter after its reporter became aware (at now, the
// database clock), and clears the alarm of every report delivered since.
func (o *Occurrences) Monitor(ctx context.Context) (MonitorReport, error) {
	var rep MonitorReport
	now, err := o.now(ctx)
	if err != nil {
		return rep, err
	}
	late, err := o.Repo.Undelivered(ctx, now, o.Policy.OccurrenceAlarmAfter, o.Policy.MaxBatch)
	if err != nil {
		return rep, err
	}
	var errs []error
	for _, u := range late {
		detail := fmt.Sprintf("occurrence report %s is not yet delivered to the authority (delivery %s %s) %.0f h after its reporter became aware; the 376/2014 Art. 4(8) deadline is %s",
			u.ReportRef, u.DeliveryID, u.DeliveryState, now.Sub(u.BecameAwareAt).Hours(), restriction.Stamp(u.DeadlineAt))
		var a deliver.Alarm
		var ok bool
		err := o.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
			var err error
			a, ok, err = tx.Outbox().RaiseAlarm(ctx, deliver.Alarm{ID: restriction.NewULID(now), Kind: deliver.AlarmOccurrenceUndelivered,
				DeliveryID: u.DeliveryID, Since: u.BecameAwareAt, Detail: clipText(detail, 1000)})
			return err
		})
		switch {
		case err != nil:
			errs = append(errs, err)
		case ok:
			rep.Raised = append(rep.Raised, a)
		}
	}
	done, err := o.Repo.DeliveredAlarms(ctx, o.Policy.MaxBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, c := range done {
		var a deliver.Alarm
		var ok bool
		err := o.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
			var err error
			a, ok, err = tx.Outbox().ClearAlarm(ctx, c.AlarmID, "delivered")
			return err
		})
		switch {
		case err != nil:
			errs = append(errs, err)
		case ok:
			rep.Cleared = append(rep.Cleared, a)
		}
	}
	for range rep.Raised {
		o.counters.Inc(CounterOccurrenceAlarms)
	}
	for range rep.Cleared {
		o.counters.Inc(CounterOccurrenceCleared)
	}
	return rep, errors.Join(errs...)
}

// RunMonitor runs Monitor every OccurrenceAlarmEvery until ctx ends.
func (o *Occurrences) RunMonitor(ctx context.Context, report func(MonitorReport, error)) {
	t := time.NewTicker(o.Policy.OccurrenceAlarmEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := o.Monitor(ctx)
		if report != nil && ctx.Err() == nil {
			report(rep, err)
		}
	}
}
