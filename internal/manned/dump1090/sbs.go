package dump1090

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// SBSColumns is the number of comma-separated columns of a line written
// by modesSendSBSOutput (net_io.c, SOURCE): "Fields 1 to 6" ... "Field 22".
const SBSColumns = 22

// The 1-based column positions of an SBS line, each named after the
// comment that numbers it in modesSendSBSOutput (SOURCE). Columns 3, 4
// and 6 are written as the literal 1 and are not read.
const (
	colMessage      = 1  // "MSG"
	colType         = 2  // the SBS message type, 1-8
	colICAO         = 5  // the ICAO address, %06X
	colRxDate       = 7  // "Fields 7 & 8 are the message reception time and date"
	colRxTime       = 8  //
	colNowDate      = 9  // "Fields 9 & 10 are the current time and date"
	colNowTime      = 10 //
	colCallsign     = 11 // "Field 11 is the callsign"
	colAltitude     = 12 // "Field 12 is the altitude"
	colGroundSpeed  = 13 // "Field 13 is the ground Speed"
	colTrack        = 14 // "Field 14 is the ground Heading" (only a ground track is written)
	colLat          = 15 // "Fields 15 and 16 are the Lat/Lon"
	colLon          = 16 //
	colVerticalRate = 17 // "Field 17 is the VerticalRate"
	colSquawk       = 18 // "Field 18 is  the Squawk"
	colAlert        = 19 // "Field 19 is the Squawk Changing Alert flag"
	colEmergency    = 20 // "Field 20 is the Squawk Emergency flag"
	colSPI          = 21 // "Field 21 is the Squawk Ident flag"
	colGround       = 22 // "Field 22 is the OnTheGround flag"
)

// SBSLine is one parsed SBS line. Values are in the feed's units, as the
// column says them; nil means the column was empty.
type SBSLine struct {
	Type   int
	ICAO24 string // as written, upper-case hex
	// RxAt is columns 7-8 and NowAt columns 9-10, read in the configured
	// zone (SOURCE assumption 3).
	RxAt     time.Time
	NowAt    time.Time
	Callsign *string
	// AltitudeFt is column 12; AltitudeGeometric is its "H" suffix
	// (SOURCE assumption 2).
	AltitudeFt        *float64
	AltitudeGeometric bool
	GroundSpeedKt     *float64
	TrackDeg          *float64
	LatDeg, LonDeg    *float64
	// VerticalRateFPM is column 17; VerticalRateGeometric its "H".
	VerticalRateFPM       *float64
	VerticalRateGeometric bool
	Squawk                *string
	Alert                 *bool
	Emergency             *bool
	SPI                   *bool
	OnGround              *bool
}

// The date and time layouts of columns 7-10 ("%04d/%02d/%02d" and
// "%02d:%02d:%02d.%03u").
const (
	sbsDateLayout = "2006/01/02"
	sbsTimeLayout = "15:04:05.000"
)

// ParseSBSLine parses one line (without its line ending) in the zone
// loc. A line that is not exactly the pinned writer's shape is refused
// with a *core.FieldError naming the column (column_<n>); it never
// panics.
func ParseSBSLine(line []byte, loc *time.Location) (SBSLine, error) {
	var out SBSLine
	cols := bytes.Split(line, []byte{','})
	if len(cols) != SBSColumns {
		return out, core.Fieldf("columns", "%d columns, the writer writes %d", len(cols), SBSColumns)
	}
	col := func(n int) string { return string(cols[n-1]) }
	if col(colMessage) != "MSG" {
		return out, core.Fieldf(colName(colMessage), "not MSG")
	}
	t, err := strconv.Atoi(col(colType))
	if err != nil || t < 1 || t > 8 {
		return out, core.Fieldf(colName(colType), "not a message type 1-8")
	}
	out.Type = t
	icao := col(colICAO)
	if len(icao) != 6 || !isHex(icao) {
		return out, core.Fieldf(colName(colICAO), "not six hex digits")
	}
	out.ICAO24 = icao
	if out.RxAt, err = sbsTime(col(colRxDate), col(colRxTime), loc); err != nil {
		return out, core.Fieldf(colName(colRxDate), "%s", err.Error())
	}
	if out.NowAt, err = sbsTime(col(colNowDate), col(colNowTime), loc); err != nil {
		return out, core.Fieldf(colName(colNowDate), "%s", err.Error())
	}
	if c := col(colCallsign); c != "" {
		out.Callsign = &c
	}
	if out.AltitudeFt, out.AltitudeGeometric, err = sbsSuffixed(col(colAltitude)); err != nil {
		return out, core.Fieldf(colName(colAltitude), "%s", err.Error())
	}
	if out.VerticalRateFPM, out.VerticalRateGeometric, err = sbsSuffixed(col(colVerticalRate)); err != nil {
		return out, core.Fieldf(colName(colVerticalRate), "%s", err.Error())
	}
	for _, f := range []struct {
		n   int
		dst **float64
	}{{colGroundSpeed, &out.GroundSpeedKt}, {colTrack, &out.TrackDeg}, {colLat, &out.LatDeg}, {colLon, &out.LonDeg}} {
		if *f.dst, err = sbsNumber(col(f.n)); err != nil {
			return out, core.Fieldf(colName(f.n), "%s", err.Error())
		}
	}
	if (out.LatDeg == nil) != (out.LonDeg == nil) {
		return out, core.Fieldf(colName(colLat), "latitude and longitude come together")
	}
	if s := col(colSquawk); s != "" {
		out.Squawk = &s
	}
	for _, f := range []struct {
		n   int
		dst **bool
	}{{colAlert, &out.Alert}, {colEmergency, &out.Emergency}, {colSPI, &out.SPI}, {colGround, &out.OnGround}} {
		if *f.dst, err = sbsFlag(col(f.n)); err != nil {
			return out, core.Fieldf(colName(f.n), "%s", err.Error())
		}
	}
	return out, nil
}

func colName(n int) string { return "column_" + strconv.Itoa(n) }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

type parseError string

func (e parseError) Error() string { return string(e) }

func sbsTime(date, clock string, loc *time.Location) (time.Time, error) {
	t, err := time.ParseInLocation(sbsDateLayout+" "+sbsTimeLayout, date+" "+clock, loc)
	if err != nil {
		return time.Time{}, parseError("not a date YYYY/MM/DD and time hh:mm:ss.mmm")
	}
	return t, nil
}

// sbsNumber is an empty column (nil) or a finite decimal number.
func sbsNumber(s string) (*float64, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) > 24 {
		return nil, parseError("too long for a number")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !core.IsFinite(v) || strings.ContainsAny(s, "xXpPnN_") {
		return nil, parseError("not a decimal number")
	}
	return &v, nil
}

// sbsSuffixed is a whole number of the writer's "%d" or "%dH".
func sbsSuffixed(s string) (*float64, bool, error) {
	if s == "" {
		return nil, false, nil
	}
	geometric := strings.HasSuffix(s, "H")
	s = strings.TrimSuffix(s, "H")
	if len(s) > 12 {
		return nil, false, parseError("too long for a whole number")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, false, parseError("not a whole number with an optional H")
	}
	v := float64(n)
	return &v, geometric, nil
}

// sbsFlag is the writer's "-1" (true), "0" (false) or empty (unknown).
func sbsFlag(s string) (*bool, error) {
	switch s {
	case "":
		return nil, nil
	case "-1":
		return manned.B(true), nil
	case "0":
		return manned.B(false), nil
	}
	return nil, parseError("not -1, 0 or empty")
}
