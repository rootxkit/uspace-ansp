package auth

import (
	"context"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Defaults of the SeenRecorder.
const (
	// DefaultSeenQueue bounds the calls waiting to be recorded; beyond
	// it a call is dropped from the log (counted), never waited for.
	DefaultSeenQueue = 1024
	// DefaultSeenFlush is how often the queue is written.
	DefaultSeenFlush = time.Second
	// MaxSeenBatch bounds the clients written in one statement batch.
	MaxSeenBatch = 256
	// MaxScopesSeen bounds the scopes kept per call (the table keeps 64).
	MaxScopesSeen = 64
)

// Counters of the SeenRecorder.
const (
	CounterSeenDropped     = "clients_seen_dropped"
	CounterSeenWritten     = "clients_seen_written"
	CounterSeenWriteFailed = "clients_seen_write_failed"
)

// SeenWriter writes oauth_clients_seen (Store).
type SeenWriter interface {
	RecordClientsSeen(ctx context.Context, seen []ClientSeen) error
}

// SeenRecorder keeps oauth_clients_seen off the request path: Record
// puts an accepted call on a bounded channel and never blocks; Run
// coalesces the calls per client and upserts them every flush period.
// A full queue drops the call (counted), and a failed write drops the
// batch (counted): the table is an observation log, the truth is the
// authority's token service.
type SeenRecorder struct {
	ch       chan ClientSeen
	flush    time.Duration
	counters core.Counters
}

// NewSeenRecorder is a recorder with a queue of size (default
// DefaultSeenQueue) flushed every flush (default DefaultSeenFlush).
func NewSeenRecorder(size int, flush time.Duration) *SeenRecorder {
	if size <= 0 {
		size = DefaultSeenQueue
	}
	if flush <= 0 {
		flush = DefaultSeenFlush
	}
	return &SeenRecorder{ch: make(chan ClientSeen, size), flush: flush}
}

// Counters are the recorder's counters.
func (s *SeenRecorder) Counters() *core.Counters { return &s.counters }

// Record queues one accepted call without blocking.
func (s *SeenRecorder) Record(c ClientSeen) {
	if len(c.Scopes) > MaxScopesSeen {
		c.Scopes = c.Scopes[:MaxScopesSeen]
	}
	c.Scopes = slices.Clone(c.Scopes)
	select {
	case s.ch <- c:
	default:
		s.counters.Inc(CounterSeenDropped)
	}
}

// Run writes the queue through w every flush period until ctx ends,
// then writes what is left with a short bound of its own. Started once
// per process on the process's context.
func (s *SeenRecorder) Run(ctx context.Context, w SeenWriter) {
	t := time.NewTicker(s.flush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			s.Flush(fctx, w)
			cancel()
			return
		case <-t.C:
			s.Flush(ctx, w)
		}
	}
}

// Flush writes every queued call, coalesced per client, in batches of
// at most MaxSeenBatch clients.
func (s *SeenRecorder) Flush(ctx context.Context, w SeenWriter) {
	for {
		batch := s.drain()
		if len(batch) == 0 {
			return
		}
		if err := w.RecordClientsSeen(ctx, batch); err != nil {
			s.counters.Add(CounterSeenWriteFailed, uint64(len(batch)))
			return
		}
		s.counters.Add(CounterSeenWritten, uint64(len(batch)))
	}
}

// drain takes queued calls until MaxSeenBatch distinct clients or an
// empty queue, merging the calls of one client.
func (s *SeenRecorder) drain() []ClientSeen {
	byClient := map[string]int{}
	var out []ClientSeen
	for len(out) < MaxSeenBatch {
		select {
		case c := <-s.ch:
			if i, ok := byClient[c.ClientID]; ok {
				merged := &out[i]
				merged.Issuer = c.Issuer
				if c.MTLSSubject != "" {
					merged.MTLSSubject = c.MTLSSubject
				}
				for _, sc := range c.Scopes {
					if !slices.Contains(merged.Scopes, sc) && len(merged.Scopes) < MaxScopesSeen {
						merged.Scopes = append(merged.Scopes, sc)
					}
				}
				continue
			}
			byClient[c.ClientID] = len(out)
			out = append(out, c)
		default:
			return out
		}
	}
	return out
}
