package manned

import "github.com/rootxkit/uspace-core/core"

// The unit conversions of the surveillance feeds, in this one file
// (WP-4: "the conversion constants in one file and a test for each").
// Every feed unit is converted at the reader boundary, never deeper.
const (
	// FeetToMetres is uspace-core's exact constant (LESSONS Z-08).
	FeetToMetres = core.FeetToMetres
	// KnotsToMetresPerSecond is exact: one international nautical mile
	// is 1852 m, one knot is 1852 m per 3600 s.
	KnotsToMetresPerSecond = 1852.0 / 3600.0
	// FeetPerMinuteToMetresPerSecond is exact: 0.3048 m per 60 s.
	FeetPerMinuteToMetresPerSecond = core.FeetToMetres / 60.0
)

// FeetToM converts feet to metres.
func FeetToM(ft float64) float64 { return ft * FeetToMetres }

// KnotsToMS converts knots to metres per second.
func KnotsToMS(kt float64) float64 { return kt * KnotsToMetresPerSecond }

// FeetPerMinToMS converts feet per minute to metres per second.
func FeetPerMinToMS(fpm float64) float64 { return fpm * FeetPerMinuteToMetresPerSecond }
