package dump1090_test

import (
	"bufio"
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/dump1090"
)

// FuzzSBSLine: no input panics the parser or the merger.
func FuzzSBSLine(f *testing.F) {
	raw, _ := os.ReadFile("testdata/sbs-from-writer-format.txt")
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f.Add(sc.Bytes())
	}
	f.Add([]byte(",,,,,,,,,,,,,,,,,,,,,"))
	f.Add([]byte("MSG,3,1,1,F0A001,1,2026/02/30,25:61:61.999,,,,-H,1e308,-0,91,181,H,,,,,"))
	pol := manned.Defaults()
	m := dump1090.NewMerger()
	f.Fuzz(func(_ *testing.T, line []byte) {
		l, err := dump1090.ParseSBSLine(line, time.UTC)
		if err != nil {
			return
		}
		_, _, _ = m.Take(&l, &pol)
	})
}

// FuzzAircraftJSON: no document panics the parser or the sampler.
func FuzzAircraftJSON(f *testing.F) {
	f.Add(aircraftDoc(f))
	f.Add([]byte(`{"now":1,"aircraft":[{"hex":"f0a001","lat":1e308,"lon":-1e308,"seen_pos":1e300,"alt_baro":"x","flight":"\u0000"}]}`))
	f.Add([]byte(`{"now":1e11,"aircraft":[{"alt_baro":[1,2],"mlat":["a"],"seen_pos":-5}]}`))
	pol := manned.Defaults()
	n := manned.NewNormaliser("fuzz", manned.SourceClassADSB, manned.StaticPolicy{Policy: pol}, nil)
	f.Fuzz(func(t *testing.T, doc []byte) {
		d, err := dump1090.ParseAircraftJSON(doc, pol.MaxJSONBytes)
		if err != nil {
			return
		}
		now := time.Unix(1790942400, 0)
		var batch []manned.RawSample
		for i := range d.Aircraft {
			if s, ok := d.Aircraft[i].Sample(now, &pol); ok {
				batch = append(batch, s)
			}
		}
		tracks := n.Take(batch, now)
		for i := range tracks {
			if err := tracks[i].ValidateWith(&pol); err != nil {
				t.Fatalf("an invalid track came out: %v", err)
			}
		}
	})
}
