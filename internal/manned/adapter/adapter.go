package adapter

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// The adapter kinds (docs/PLAN.md section 5.1 adapters.kind; atm_api
// waits for the data-release agreement, section 15 gap 12).
const (
	KindReplay        = "replay"
	KindDump1090SBS   = "dump1090_sbs"
	KindDump1090JSON  = "dump1090_json"
	KindASTERIXCat021 = "asterix_cat021"
)

// Kinds is every kind this build can be configured with.
var Kinds = []string{KindReplay, KindDump1090SBS, KindDump1090JSON, KindASTERIXCat021}

// Adapter reads one surveillance feed. It never writes to its feed:
// no adapter type has a send path towards the feed or an aircraft
// (CLAUDE.md rule 1).
type Adapter interface {
	// Kind is one of Kinds.
	Kind() string
	// Run opens the feed read-only, reports it to sink and returns when
	// ctx ends or the feed is gone; the runner reconnects (B-08). It
	// must not panic on any input.
	Run(ctx context.Context, sink Sink) error
}

// Sink is where an adapter reports what it reads. It is the runner's
// side of the feed: samples go through a bounded queue to the
// normaliser, and everything else is counted (E-09). Run takes a Sink
// instead of a bare channel of samples so that a connected feed with an
// empty sky is visibly connected, and so that input which is not a
// sample (a heartbeat, an unparsable line) is still a read.
type Sink interface {
	// Connected says the feed is open.
	Connected()
	// Heard says input arrived at the adapter's clock now (any line,
	// heartbeat or poll): the read the following samples come from.
	Heard()
	// Sample queues one sample of the current read; it blocks while the
	// queue is full and returns ctx's error when ctx ends.
	Sample(ctx context.Context, s manned.RawSample) error
	// Refuse counts input that is not a sample: refused and
	// refused_<name>.
	Refuse(name string)
	// Count counts name (merged_lines, skipped_no_position, ...).
	Count(name string)
	// Policy is the policy of the moment.
	Policy() manned.Policy
	// Now is the adapter's clock.
	Now() time.Time
}

// ErrDeferred is returned by an adapter kind that exists only as a stub
// (asterix_cat021), so a misconfigured deployment fails loudly. It is
// permanent: the runner does not retry it.
var ErrDeferred = fmt.Errorf("%w: adapter kind deferred", ErrPermanent)

// Factory builds an adapter of one kind.
type Factory func() (Adapter, error)

// Registry maps kinds to factories; cmd/manned-adapter fills it with the
// kinds of this build.
type Registry struct {
	factories map[string]Factory
}

// Register adds kind; a kind not in Kinds or registered twice is an
// error.
func (r *Registry) Register(kind string, f Factory) error {
	if !slices.Contains(Kinds, kind) {
		return fmt.Errorf("adapter: unknown kind %q", kind)
	}
	if r.factories == nil {
		r.factories = map[string]Factory{}
	}
	if _, ok := r.factories[kind]; ok {
		return fmt.Errorf("adapter: kind %q registered twice", kind)
	}
	r.factories[kind] = f
	return nil
}

// Build is the adapter of kind.
func (r *Registry) Build(kind string) (Adapter, error) {
	f, ok := r.factories[kind]
	if !ok {
		return nil, fmt.Errorf("adapter: kind %q is not registered (registered: %v)", kind, r.Registered())
	}
	return f()
}

// Registered is the registered kinds, sorted.
func (r *Registry) Registered() []string {
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
