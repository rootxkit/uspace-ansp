package dump1090

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

// Counters of the SBS reader.
const (
	CounterHeartbeats        = "heartbeats"          // empty lines (send_sbs_heartbeat)
	CounterMergedLines       = "merged_lines"        // lines without a position, held for the next one
	CounterEvictedSBSHeld    = "evicted_sbs_held"    // held SBS fields dropped at max_aircraft (E-10)
	CounterFeedIdleTimeouts  = "feed_idle_timeouts"  // no input for feed_idle_timeout_s
	CounterSkippedNoPosition = "skipped_no_position" // aircraft.json aircraft without a position
	RefusedSBSLine           = "sbs_line"            // refused_sbs_line: a line that does not parse
	RefusedLineTooLong       = "line_too_long"       // refused_line_too_long: a line beyond max_line_bytes
)

// heldField is one value of an SBS line without a position, with the
// feed time it was received at.
type heldField[T any] struct {
	v  *T
	at time.Time
}

func (h *heldField[T]) set(v *T, at time.Time) {
	if v != nil {
		x := *v
		h.v, h.at = &x, at
	}
}

// get is the value when it is no older than maxAge before at on the
// feed's clock (it is only ever compared with the feed's own times).
func (h *heldField[T]) get(at time.Time, maxAge time.Duration) *T {
	if h.v == nil || at.Sub(h.at) > maxAge || h.at.After(at) {
		return nil
	}
	x := *h.v
	return &x
}

type sbsHeld struct {
	callsign  heldField[string]
	altBaroM  heldField[float64]
	altGeomM  heldField[float64]
	gsMS      heldField[float64]
	trackDeg  heldField[float64]
	vrateMS   heldField[float64]
	squawk    heldField[string]
	emergency heldField[bool]
	spi       heldField[bool]
	lastAt    time.Time
}

// Merger turns SBS lines into samples. dump1090 writes a position only
// on some lines (column 15/16) and the callsign, speed, track, vertical
// rate and squawk on others, so the fields of lines without a position
// are held per aircraft (bounded by max_aircraft, eviction counted) and
// merged into the next line that has one when they are no older than
// held_field_max_age_s on the feed's clock. Single goroutine.
type Merger struct {
	held map[string]*sbsHeld
}

// NewMerger is an empty merger.
func NewMerger() *Merger { return &Merger{held: map[string]*sbsHeld{}} }

// Take merges l and returns the sample of l when it carries a position;
// evicted reports an aircraft dropped from the held set.
func (m *Merger) Take(l *SBSLine, pol *manned.Policy) (s manned.RawSample, ok, evicted bool) {
	h, ok := m.held[l.ICAO24]
	if !ok {
		if len(m.held) >= pol.MaxAircraft {
			var oldest string
			var at time.Time
			first := true
			for k, v := range m.held {
				if first || v.lastAt.Before(at) {
					oldest, at, first = k, v.lastAt, false
				}
			}
			delete(m.held, oldest)
			evicted = true
		}
		h = &sbsHeld{}
		m.held[l.ICAO24] = h
	}
	at := l.RxAt
	h.lastAt = at
	altM := convert(l.AltitudeFt, manned.FeetToM)
	if l.AltitudeGeometric {
		h.altGeomM.set(altM, at)
	} else {
		h.altBaroM.set(altM, at)
	}
	h.callsign.set(l.Callsign, at)
	h.gsMS.set(convert(l.GroundSpeedKt, manned.KnotsToMS), at)
	h.trackDeg.set(l.TrackDeg, at)
	h.vrateMS.set(convert(l.VerticalRateFPM, manned.FeetPerMinToMS), at)
	h.squawk.set(l.Squawk, at)
	h.emergency.set(l.Emergency, at)
	h.spi.set(l.SPI, at)
	if l.LatDeg == nil || l.LonDeg == nil {
		return manned.RawSample{}, false, evicted
	}
	maxAge := manned.Seconds(pol.HeldFieldMaxAgeS)
	rx, now := l.RxAt, l.NowAt
	s = manned.RawSample{
		FeedTS: &rx, FeedNow: &now, ICAO24: l.ICAO24,
		Position:     &manned.LatLonSample{LatDeg: *l.LatDeg, LonDeg: *l.LonDeg},
		Callsign:     h.callsign.get(at, maxAge),
		AltPressureM: h.altBaroM.get(at, maxAge),
		AltWGS84M:    h.altGeomM.get(at, maxAge),
		GSMS:         h.gsMS.get(at, maxAge),
		TrackDeg:     h.trackDeg.get(at, maxAge),
		VRateMS:      h.vrateMS.get(at, maxAge),
		Squawk:       h.squawk.get(at, maxAge),
		Emergency:    h.emergency.get(at, maxAge),
		SPI:          h.spi.get(at, maxAge),
		Quality:      map[string]any{"sbs_message_type": float64(l.Type)},
	}
	if l.Alert != nil {
		s.Quality["squawk_changing_alert"] = *l.Alert
	}
	if l.OnGround != nil {
		s.Quality["on_the_ground"] = *l.OnGround
	}
	if l.VerticalRateFPM != nil {
		s.Quality["vertical_rate_geometric"] = l.VerticalRateGeometric
	}
	return s, true, evicted
}

// Held is the number of aircraft whose fields are held.
func (m *Merger) Held() int { return len(m.held) }

func convert(v *float64, f func(float64) float64) *float64 {
	if v == nil {
		return nil
	}
	x := f(*v)
	return &x
}

// SBSConfig configures the SBS adapter.
type SBSConfig struct {
	// Addr is the BaseStation output, host:port (dump1090 --net-sbs-port,
	// 30003 by convention).
	Addr string
	// Location is the zone of columns 7-10 (SOURCE assumption 3).
	Location *time.Location
	// DialTimeout bounds one connection attempt; zero is 5 s.
	DialTimeout time.Duration
}

// SBSAdapter is a TCP client of dump1090's BaseStation output. It only
// reads: the connection is never written to (CLAUDE.md rule 1).
type SBSAdapter struct {
	cfg SBSConfig
}

// NewSBSAdapter checks cfg.
func NewSBSAdapter(cfg SBSConfig) (*SBSAdapter, error) {
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return nil, fmt.Errorf("%w: dump1090_sbs: address %q is not host:port", adapter.ErrPermanent, cfg.Addr)
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	return &SBSAdapter{cfg: cfg}, nil
}

// Kind is dump1090_sbs.
func (*SBSAdapter) Kind() string { return adapter.KindDump1090SBS }

// Run connects, reads lines until the feed ends, goes idle for
// feed_idle_timeout_s, or ctx ends.
func (a *SBSAdapter) Run(ctx context.Context, sink adapter.Sink) error {
	d := net.Dialer{Timeout: a.cfg.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", a.cfg.Addr)
	if err != nil {
		return fmt.Errorf("dump1090_sbs: connect: %w", err)
	}
	sink.Connected()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	return a.read(ctx, deadlineReader{conn: conn, sink: sink}, sink)
}

// deadlineReader is the read side of the connection: every read is
// bounded by feed_idle_timeout_s. It has no write method.
type deadlineReader struct {
	conn interface {
		Read([]byte) (int, error)
		SetReadDeadline(time.Time) error
	}
	sink adapter.Sink
}

func (d deadlineReader) Read(p []byte) (int, error) {
	pol := d.sink.Policy()
	_ = d.conn.SetReadDeadline(d.sink.Now().Add(manned.Seconds(pol.FeedIdleTimeoutS)))
	return d.conn.Read(p)
}

// read reads lines from r until it ends.
func (a *SBSAdapter) read(ctx context.Context, r io.Reader, sink adapter.Sink) error {
	pol := sink.Policy()
	br := bufio.NewReaderSize(r, pol.MaxLineBytes)
	merger := NewMerger()
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			sink.Heard()
			sink.Refuse(RefusedLineTooLong)
			if err := skipLine(br); err != nil {
				return a.ended(ctx, err, sink)
			}
			continue
		}
		if err != nil {
			return a.ended(ctx, err, sink)
		}
		sink.Heard()
		line = trimEOL(line)
		if len(line) == 0 {
			sink.Count(CounterHeartbeats)
			continue
		}
		pol = sink.Policy()
		l, perr := ParseSBSLine(line, a.cfg.Location)
		if perr != nil {
			sink.Refuse(RefusedSBSLine)
			continue
		}
		s, ok, evicted := merger.Take(&l, &pol)
		if evicted {
			sink.Count(CounterEvictedSBSHeld)
		}
		if !ok {
			sink.Count(CounterMergedLines)
			continue
		}
		if err := sink.Sample(ctx, s); err != nil {
			return err
		}
	}
}

func (a *SBSAdapter) ended(ctx context.Context, err error, sink adapter.Sink) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		sink.Count(CounterFeedIdleTimeouts)
		return fmt.Errorf("dump1090_sbs: no input for feed_idle_timeout_s: %w", err)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("dump1090_sbs: the feed closed the connection: %w", err)
	}
	return fmt.Errorf("dump1090_sbs: read: %w", err)
}

// skipLine discards the rest of an over-long line.
func skipLine(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
