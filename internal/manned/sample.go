package manned

import "time"

// RawSample is what a feed said about one aircraft at one read, before
// any judgement: converted to SI units at the reader boundary (units.go)
// and nothing else. Pointers are nil when the feed did not say.
type RawSample struct {
	// FeedTS is the time of the sample on the feed's own clock, nil when
	// the feed gives none (T-12). It is only ever compared with other
	// times of the same feed (T-01).
	FeedTS *time.Time
	// FeedNow is the feed's clock when it emitted the sample (SBS field
	// 10, aircraft.json "now"), nil when it gives none. It is the
	// reference "now" of the batch on the feed's clock.
	FeedNow *time.Time
	// ReadAt is the adapter's clock when the sample was read; the
	// runner's sink stamps it when the reader leaves it zero.
	ReadAt time.Time
	// AfterGap is the silence on the feed before the read that carried
	// this sample (set by the runner's sink).
	AfterGap time.Duration
	// Backlog is the reader's or runner's verdict that the sample is
	// history (aircraft.json position older than max_age_s, or a burst
	// after a stall with no time base).
	Backlog bool

	ICAO24       string
	Callsign     *string
	Position     *LatLonSample
	AltPressureM *float64
	AltWGS84M    *float64
	GSMS         *float64
	TrackDeg     *float64
	VRateMS      *float64
	Emergency    *bool
	SPI          *bool
	Squawk       *string
	// SourceClass overrides the adapter's configured class when the feed
	// says (a replay file header); empty keeps the configured one.
	SourceClass string
	Quality     map[string]any
}

// LatLonSample is a position as read, not yet validated.
type LatLonSample struct {
	LatDeg, LonDeg float64
}

// F is a pointer to v (readers and tests).
func F(v float64) *float64 { return &v }

// B is a pointer to v.
func B(v bool) *bool { return &v }

// S is a pointer to v.
func S(v string) *string { return &v }

// T is a pointer to v.
func T(v time.Time) *time.Time { return &v }
