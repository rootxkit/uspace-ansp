package replay_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/manned/replay"
)

// FuzzReplayFrame: no record panics the parser or the sampler.
func FuzzReplayFrame(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join(replayDir, "two-aircraft-converging.ndjson"))
	for i, l := range strings.Split(string(raw), "\n") {
		if i > 3 {
			break
		}
		f.Add([]byte(l))
	}
	f.Add([]byte(`{"schema":"track/manned/v1","ts":"9999-99-99","body":{"position":{"lat":null}}}`))
	f.Fuzz(func(_ *testing.T, line []byte) {
		_, _ = replay.ParseHeader(line)
		r, err := replay.ParseRecord(line, 64<<10)
		if err != nil {
			return
		}
		ts, err := r.Time()
		if err != nil {
			return
		}
		_ = r.Sample(ts)
	})
}
