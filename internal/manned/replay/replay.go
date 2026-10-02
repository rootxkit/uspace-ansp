package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

// HeaderSchema names the first line of a replay file.
const HeaderSchema = "replay/header/v1"

// Header is the first line of a replay file: it says the file is
// synthetic (CLAUDE.md rule 11: replay data is synthetic and says so)
// and gives the source class of every record.
type Header struct {
	Schema      string `json:"schema"`
	Synthetic   bool   `json:"synthetic"`
	SourceClass string `json:"source_class"`
	Description string `json:"description"`
}

// Record is one line after the header: a track/manned/v1 message as the
// adapter publishes it (envelope and body), of which the replay reads
// ts and the body's measurements. trust, source, state and the other
// times are the replay's own (trust surveillance, placed on replay).
type Record struct {
	Schema string     `json:"schema"`
	TS     *string    `json:"ts"`
	Body   RecordBody `json:"body"`
}

// RecordBody is the measured part of a track/manned/v1 body.
type RecordBody struct {
	ICAO24   string  `json:"icao24"`
	Callsign *string `json:"callsign"`
	Position *struct {
		Lat *float64 `json:"lat"`
		Lng *float64 `json:"lng"`
	} `json:"position"`
	AltPressureM *float64       `json:"alt_pressure_m"`
	AltWGS84M    *float64       `json:"alt_wgs84_m"`
	GSMS         *float64       `json:"gs_ms"`
	TrackDeg     *float64       `json:"track_deg"`
	VRateMS      *float64       `json:"vrate_ms"`
	Emergency    *bool          `json:"emergency"`
	SPI          *bool          `json:"spi"`
	Squawk       *string        `json:"squawk"`
	Quality      map[string]any `json:"quality"`
}

// ParseHeader decodes and checks the header line.
func ParseHeader(line []byte) (Header, error) {
	var h Header
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return Header{}, core.Fieldf("header", "not a %s line", HeaderSchema)
	}
	switch {
	case h.Schema != HeaderSchema:
		return Header{}, core.Fieldf("header.schema", "must be %s", HeaderSchema)
	case !h.Synthetic:
		return Header{}, core.Fieldf("header.synthetic", "must be true: replay data is synthetic and says so")
	case !manned.ValidSourceClass(h.SourceClass):
		return Header{}, core.Fieldf("header.source_class", "unknown source class %q", h.SourceClass)
	}
	return h, nil
}

// ParseRecord decodes one record line of at most maxBytes. It refuses
// with a *core.FieldError and never panics.
func ParseRecord(line []byte, maxBytes int) (Record, error) {
	var r Record
	if len(line) > maxBytes {
		return r, core.Fieldf("record", "longer than %d bytes", maxBytes)
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, core.Fieldf("record", "not a track/manned/v1 record")
	}
	if r.Schema != manned.SchemaTrack {
		return Record{}, core.Fieldf("record.schema", "must be %s", manned.SchemaTrack)
	}
	return r, nil
}

// Time is the record's ts, nil when absent or null.
func (r *Record) Time() (*time.Time, error) {
	if r.TS == nil {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, *r.TS)
	if err != nil {
		return nil, core.Fieldf("ts", "not an RFC 3339 time")
	}
	return &t, nil
}

// Sample is the record as a raw sample whose feed time is ts.
func (r *Record) Sample(ts *time.Time) manned.RawSample {
	s := manned.RawSample{
		ICAO24: r.Body.ICAO24, Callsign: r.Body.Callsign,
		AltPressureM: r.Body.AltPressureM, AltWGS84M: r.Body.AltWGS84M, GSMS: r.Body.GSMS, TrackDeg: r.Body.TrackDeg,
		VRateMS: r.Body.VRateMS, Emergency: r.Body.Emergency, SPI: r.Body.SPI, Squawk: r.Body.Squawk, Quality: r.Body.Quality,
	}
	if p := r.Body.Position; p != nil && p.Lat != nil && p.Lng != nil {
		s.Position = &manned.LatLonSample{LatDeg: *p.Lat, LonDeg: *p.Lng}
	}
	if ts != nil {
		t, n := *ts, *ts
		s.FeedTS, s.FeedNow = &t, &n
	}
	return s
}

// Config configures the replay adapter.
type Config struct {
	File string
	// Allowed is ANSP_ADAPTER_REPLAY_ALLOWED; never on by default (06 T11).
	Allowed bool
	// Speed scales the wall time between records (1 is real time).
	Speed float64
	// Loop starts again at the end, shifting the records' times forward
	// so they stay in order on the replayed clock.
	Loop bool
}

// Counters of the replay adapter.
const (
	RefusedRecord        = "replay_record" // refused_replay_record
	CounterLoops         = "replay_loops"
	CounterReplayEnded   = "replay_ended"
	maxSpeed             = 1000
	loopGap              = time.Second
	errReplayNotAllowed  = "replay is not allowed: set ANSP_ADAPTER_REPLAY_ALLOWED=true (never on by default, 06 T11)"
	errReplaySpeedBounds = "replay speed must be greater than 0 and at most 1000"
)

// Adapter replays a synthetic NDJSON file of track/manned/v1 records.
type Adapter struct {
	cfg    Config
	header Header
}

// New refuses to build a replay unless it is allowed, the speed is
// sane and the file starts with a synthetic header.
func New(cfg Config) (*Adapter, error) {
	if !cfg.Allowed {
		return nil, fmt.Errorf("%w: %s", adapter.ErrPermanent, errReplayNotAllowed)
	}
	if !core.IsFinite(cfg.Speed) || cfg.Speed <= 0 || cfg.Speed > maxSpeed {
		return nil, fmt.Errorf("%w: %s", adapter.ErrPermanent, errReplaySpeedBounds)
	}
	f, err := os.Open(cfg.File)
	if err != nil {
		return nil, fmt.Errorf("%w: replay: %w", adapter.ErrPermanent, err)
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, 64<<10)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: replay: %w", adapter.ErrPermanent, err)
	}
	h, err := ParseHeader(bytes.TrimSpace(line))
	if err != nil {
		return nil, fmt.Errorf("%w: replay %s: %w", adapter.ErrPermanent, cfg.File, err)
	}
	return &Adapter{cfg: cfg, header: h}, nil
}

// Header is the file's header.
func (a *Adapter) Header() Header { return a.header }

// Kind is replay.
func (*Adapter) Kind() string { return adapter.KindReplay }

// Run replays the file at Speed, once or in a loop. After the last
// record of a replay without a loop it stays connected and silent until
// ctx ends (the status then says stale), so a finished replay is never
// mistaken for a reconnecting feed.
func (a *Adapter) Run(ctx context.Context, sink adapter.Sink) error {
	sink.Connected()
	var offset time.Duration
	for {
		first, last, err := a.once(ctx, sink, offset)
		if err != nil {
			return err
		}
		if !a.cfg.Loop {
			sink.Count(CounterReplayEnded)
			<-ctx.Done()
			return ctx.Err()
		}
		sink.Count(CounterLoops)
		if first != nil && last != nil {
			offset += last.Sub(*first) + loopGap
		}
		if err := sleepUntil(ctx, sink, sink.Now().Add(time.Duration(float64(loopGap)/a.cfg.Speed))); err != nil {
			return err
		}
	}
}

// once replays the file one time with the records' times shifted by
// offset; it returns the first and last record times seen (unshifted).
func (a *Adapter) once(ctx context.Context, sink adapter.Sink, offset time.Duration) (first, last *time.Time, err error) {
	f, err := os.Open(a.cfg.File)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: replay: %w", adapter.ErrPermanent, err)
	}
	defer func() { _ = f.Close() }()
	pol := sink.Policy()
	br := bufio.NewReaderSize(f, pol.MaxRecordBytes)
	if _, err := br.ReadBytes('\n'); err != nil {
		return nil, nil, fmt.Errorf("%w: replay: header: %w", adapter.ErrPermanent, err)
	}
	var wallStart time.Time
	for {
		line, rerr := br.ReadSlice('\n')
		if errors.Is(rerr, bufio.ErrBufferFull) {
			sink.Heard()
			sink.Refuse(RefusedRecord)
			if err := skipLine(br); err != nil {
				return first, last, nil
			}
			continue
		}
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			r, perr := ParseRecord(trimmed, pol.MaxRecordBytes)
			var ts *time.Time
			if perr == nil {
				ts, perr = r.Time()
			}
			if perr != nil {
				sink.Heard()
				sink.Refuse(RefusedRecord)
			} else {
				if ts != nil {
					if first == nil {
						first, wallStart = ts, sink.Now()
					}
					due := wallStart.Add(time.Duration(float64(ts.Sub(*first)) / a.cfg.Speed))
					if err := sleepUntil(ctx, sink, due); err != nil {
						return first, last, err
					}
					last = ts
					shifted := ts.Add(offset)
					ts = &shifted
				}
				sink.Heard()
				if err := sink.Sample(ctx, r.Sample(ts)); err != nil {
					return first, last, err
				}
			}
		}
		if errors.Is(rerr, io.EOF) {
			return first, last, nil
		}
		if rerr != nil {
			return first, last, fmt.Errorf("replay: read: %w", rerr)
		}
	}
}

func sleepUntil(ctx context.Context, sink adapter.Sink, due time.Time) error {
	d := due.Sub(sink.Now())
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func skipLine(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
}
