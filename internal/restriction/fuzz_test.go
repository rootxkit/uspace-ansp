package restriction

import (
	"testing"
	"time"
)

// FuzzRestrictionRequest: any body of POST /v1/restriction-requests or
// /v1/restrictions is decoded, validated and turned into the feature it
// would make without a panic (06 T9: inbound JSON is untrusted).
func FuzzRestrictionRequest(f *testing.F) {
	f.Add([]byte(createBody), true)
	f.Add([]byte(`{"client_ref":"x","geometry":{"type":"Point","coordinates":[44.8,41.7]},"radius_m":1e308}`), false)
	f.Add([]byte(`{"geometry":{"type":"Polygon","coordinates":[[[180,90],[-180,-90],[0,0],[180,90]]]},"lower_m":-1e308,"upper_m":1e308}`), true)
	f.Add([]byte(`{"geometry":null}`), false)
	f.Fuzz(func(_ *testing.T, body []byte, create bool) {
		kind := BodyRequest
		if create {
			kind = BodyCreate
		}
		_, in, errs := DecodeArea(body, kind)
		if len(errs) > 0 {
			return
		}
		_, _ = Validate(in, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	})
}

// FuzzDecodeReason: any transition body is decoded without a panic.
func FuzzDecodeReason(f *testing.F) {
	f.Add([]byte(`{"reason":"x","ends_at":"2026-10-02T18:00:00.000Z"}`))
	f.Add([]byte(`{"zone_type":1}`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		b, errs := DecodeReason(body, true, true, true)
		if len(errs) == 0 {
			_, _ = b.EndOf()
		}
	})
}
