package feed

import (
	"context"

	"github.com/rootxkit/uspace-core/core"
)

// DefaultProductQueue bounds the feed_products samples waiting for the
// database (E-10).
const DefaultProductQueue = 1024

// Counters of the product queue.
const (
	CounterProductsWritten = "feed_products_written"
	CounterProductsFailed  = "feed_products_failed"
)

// ProductQueue takes feed_products samples without blocking the stream
// (a full queue drops the sample, counted) and writes them in Run.
type ProductQueue struct {
	ch       chan Product
	counters *core.Counters
}

// NewProductQueue is a queue of size (DefaultProductQueue when not
// positive); counters may be nil.
func NewProductQueue(size int, counters *core.Counters) *ProductQueue {
	if size <= 0 {
		size = DefaultProductQueue
	}
	if counters == nil {
		counters = &core.Counters{}
	}
	return &ProductQueue{ch: make(chan Product, size), counters: counters}
}

// Counters are the queue's counters.
func (q *ProductQueue) Counters() *core.Counters { return q.counters }

// Record queues p, or drops it and counts when the queue is full.
func (q *ProductQueue) Record(p Product) {
	select {
	case q.ch <- p:
	default:
		q.counters.Inc(CounterProductsDropped)
	}
}

// Run writes every queued sample with insert until ctx ends; a failed
// write is counted and the sample dropped (it is a sampled record, not
// the record of the samples, which is manned_tracks).
func (q *ProductQueue) Run(ctx context.Context, insert func(ctx context.Context, p Product) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-q.ch:
			if err := insert(ctx, p); err != nil {
				q.counters.Inc(CounterProductsFailed)
				continue
			}
			q.counters.Inc(CounterProductsWritten)
		}
	}
}
