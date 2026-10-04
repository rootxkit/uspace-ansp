package obs

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// Counters of ServerErrors (E-09).
const (
	// CounterInternalErrors counts every request answered 500, whatever
	// route answered it, a recovered panic included.
	CounterInternalErrors = "http_internal_errors"
	// CounterPanics counts the handler panics recovered (each is also
	// one CounterInternalErrors).
	CounterPanics = "http_panics"
)

// MsgInternalError is the message of the log line of a 500 (and of a
// recovered panic, whose status field says what the client got).
const MsgInternalError = "request answered 500"

// maxStackBytes bounds the stack a recovered panic logs.
const maxStackBytes = 8 << 10

// ServerErrors is the middleware that makes no 500 silent: every request
// answered 500 is counted (CounterInternalErrors) and logged once at
// error level with its method, route pattern, path, duration and the
// cause the handler noted (apierr.NoteCause, apierr.WriteInternal; "not
// noted" when it noted none). A handler panic is recovered, counted
// (CounterPanics), logged with its stack and answered 500 internal when
// nothing was written yet; when the header was already written, the
// response is aborted with http.ErrAbortHandler so the client sees a
// transport error, not a truncated answer. A handler's own
// http.ErrAbortHandler is passed on, not counted. Neither
// the query, the headers nor the body is logged: they may hold
// credentials.
func ServerErrors(logger *slog.Logger, counters *core.Counters) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if counters == nil {
		counters = &core.Counters{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cause := apierr.WithCause(r.Context())
			r = r.WithContext(ctx)
			sw := &statusWriter{ResponseWriter: w}
			start := time.Now()
			defer func() {
				v := recover()
				if v == nil {
					if sw.status == http.StatusInternalServerError {
						internalError(logger, counters, r, start, http.StatusInternalServerError, cause.Err(), nil)
					}
					return
				}
				if v == http.ErrAbortHandler { //nolint:errorlint // the sentinel is compared as net/http does
					panic(v) //nolint:forbidigo // net/http's own abort, passed on to the server that raised it
				}
				counters.Inc(CounterPanics)
				stack := debug.Stack()
				if len(stack) > maxStackBytes {
					stack = stack[:maxStackBytes]
				}
				// The status the client got: 500, or the one written before
				// the panic (0 for a hijacked connection).
				begun := sw.wrote
				if !begun && !sw.hijacked {
					apierr.Write(sw, http.StatusInternalServerError, apierr.Internal().At(r))
				}
				internalError(logger, counters, r, start, sw.status, fmt.Errorf("panic: %v", v), stack)
				if begun {
					// The status and maybe part of the body are out: finishing
					// the response would hand the client a truncated success.
					// net/http's own abort closes the connection instead, so
					// the client sees a transport error; it is logged above.
					panic(http.ErrAbortHandler) //nolint:forbidigo // aborts the response already begun
				}
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

func internalError(logger *slog.Logger, counters *core.Counters, r *http.Request, start time.Time, status int, cause error, stack []byte) {
	counters.Inc(CounterInternalErrors)
	why := "not noted"
	if cause != nil {
		why = cause.Error()
	}
	attrs := []slog.Attr{
		slog.String("method", r.Method),
		slog.String("route", r.Pattern),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.String("error", why),
	}
	if stack != nil {
		attrs = append(attrs, slog.String("stack", string(stack)))
	}
	logger.LogAttrs(r.Context(), slog.LevelError, MsgInternalError, attrs...)
}

// statusWriter records the status written. It keeps the writer's
// Flusher and Hijacker (the console streams upgrade through it) and
// unwraps for http.ResponseController.
type statusWriter struct {
	http.ResponseWriter
	status   int
	wrote    bool
	hijacked bool
}

// WriteHeader records the first final status and writes it.
func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote && code >= 200 {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write records an implicit 200 and writes b.
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// Flush flushes the underlying writer when it can.
func (w *statusWriter) Flush() {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack hands the connection over (a WebSocket upgrade).
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, rw, err
}

// Unwrap is the underlying writer (http.ResponseController).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var (
	_ http.Flusher  = (*statusWriter)(nil)
	_ http.Hijacker = (*statusWriter)(nil)
)
