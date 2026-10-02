package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// GenesisHash is the prev_hash of the first row ever written.
var GenesisHash = strings.Repeat("0", 64)

// tsLayout renders ts in the canonical row: UTC, always six fractional
// digits, the precision PostgreSQL stores.
const tsLayout = "2006-01-02T15:04:05.000000Z07:00"

// Row is a stored event, as Verify and Query read it.
type Row struct {
	ID         int64           `json:"id"`
	TS         time.Time       `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	Purpose    string          `json:"purpose"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

// canonicalRow fixes the field order of the hashed document.
type canonicalRow struct {
	ID         int64           `json:"id"`
	TS         string          `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	Purpose    string          `json:"purpose"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
}

// storedTime is t as PostgreSQL stores a timestamptz: UTC, microseconds.
func storedTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// Canonical is the JSON document a row's hash covers: every column but
// prev_hash and hash, in a fixed order, ts in UTC with microseconds, the
// payload in canonical form. prev_hash is prepended by Hash.
func Canonical(r *Row) ([]byte, error) {
	payload, err := CanonicalPayload(r.Payload)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err = enc.Encode(canonicalRow{
		ID: r.ID, TS: storedTime(r.TS).Format(tsLayout), ActorType: r.ActorType, ActorID: r.ActorID,
		Purpose: r.Purpose, EntityType: r.EntityType, EntityID: r.EntityID, EventType: r.EventType,
		Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("canonical row: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CanonicalPayload re-encodes a JSON object with sorted keys, no
// insignificant whitespace and numbers kept as written. Applied to the
// text PostgreSQL returns for a jsonb (which has normalised the numbers
// already), it gives the same bytes on write and on verification.
func CanonicalPayload(doc []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("payload: trailing data after the JSON object")
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("payload: must be a JSON object")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Hash is hex(sha256(prev_hash || canonical row)), the value stored in
// the row's hash column (spec 06 T7).
func Hash(r *Row) (string, error) {
	c, err := Canonical(r)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = io.WriteString(h, r.PrevHash)
	_, _ = h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MonthStart is the first instant of t's UTC month.
func MonthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// monthLockName names a month's advisory lock ("events:2026-10").
func monthLockName(month time.Time) string { return "events:" + month.Format("2006-01") }
