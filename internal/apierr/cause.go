package apierr

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// Cause is what a request's 500 was made from: the error a handler could
// not answer as a refusal. The body never carries it (Internal); the
// server's log line does (obs.ServerErrors), so that a 500 is never
// silent. The first cause noted is kept.
type Cause struct {
	mu  sync.Mutex
	err error
}

// Err is the cause noted, nil when none was.
func (c *Cause) Err() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Cause) note(err error) {
	if c == nil || err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

type causeKey struct{}

// WithCause gives ctx a Cause that WriteError and WriteInternal fill on
// every request served under it, also through the copies of the request
// that later middleware makes (WithContext keeps the value).
func WithCause(ctx context.Context) (context.Context, *Cause) {
	c := &Cause{}
	return context.WithValue(ctx, causeKey{}, c), c
}

// NoteCause records err as the cause of the 500 r is answered with. It
// does nothing for a request without a Cause (WithCause).
func NoteCause(r *http.Request, err error) {
	if r == nil {
		return
	}
	c, _ := r.Context().Value(causeKey{}).(*Cause)
	c.note(err)
}

// WriteInternal answers 500 internal (its text is not written) and
// records cause for the server's log line.
func WriteInternal(w http.ResponseWriter, r *http.Request, cause error) {
	if cause == nil {
		cause = errors.New("an internal error without a cause")
	}
	NoteCause(r, cause)
	Write(w, http.StatusInternalServerError, Internal().At(r))
}
