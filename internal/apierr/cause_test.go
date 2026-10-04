package apierr

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

// An error that is no problem and is answered 500 is the cause, also
// through a copy of the request; a problem and a field error answered
// 400 are not.
func TestWriteErrorNotesTheCause(t *testing.T) {
	cause := errors.New("check constraint violated")
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"a plain error", cause, http.StatusInternalServerError},
		{"a joined one", errors.Join(errors.New("insert"), cause), http.StatusInternalServerError},
		{"an internal problem", Internal(), http.StatusInternalServerError},
		{"a field error", core.Fieldf("Idempotency-Key", "is not a key"), http.StatusBadRequest},
		{"a refusal", Unavailable(0, "later"), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/restrictions", nil)
			ctx, c := WithCause(r.Context())
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()
			WriteError(w, r.WithContext(r.Context()), tc.err) // a later middleware's copy
			if w.Code != tc.status {
				t.Fatalf("status %d", w.Code)
			}
			switch {
			case tc.status != http.StatusInternalServerError || errors.As(tc.err, new(*Problem)):
				if c.Err() != nil {
					t.Fatalf("noted %v", c.Err())
				}
			case c.Err() == nil || c.Err().Error() != tc.err.Error():
				t.Fatalf("noted %v, want %v", c.Err(), tc.err)
			}
		})
	}
}

func TestWriteInternal(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx, c := WithCause(r.Context())
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	WriteInternal(w, r, errors.New("first"))
	NoteCause(r, errors.New("second"))
	if w.Code != http.StatusInternalServerError || c.Err() == nil || c.Err().Error() != "first" {
		t.Fatalf("%d %v", w.Code, c.Err())
	}
	// Without a Cause on the request, and without a cause at all.
	w = httptest.NewRecorder()
	WriteInternal(w, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatal(w.Code)
	}
	var none *Cause
	if none.Err() != nil {
		t.Fatal("a nil Cause noted something")
	}
}
