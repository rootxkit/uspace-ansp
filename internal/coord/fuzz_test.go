package coord

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzAnnexVNotice: the intake never panics on untrusted bytes, never
// stores a refused body, and stores exactly what it accepted.
func FuzzAnnexVNotice(f *testing.F) {
	for _, dir := range []string{examples, filepath.Join(examples, "invalid")} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && !e.IsDir() {
				f.Add(b)
			}
		}
	}
	f.Add([]byte(`{"schema":"coordination/annex_v/v1","intents":[{"volumes":[{"volume":{"outline_circle":{"center":{"lat":1e400}}}}]}]}`))
	f.Add([]byte(`{"intents":[null,{},[]],"nonconformance":{"position":{"lat":"x"}}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fx := newFixture(t)
		_, errs := DecodeNotice(body)
		rec, _, err := fx.svc.Submit(context.Background(), "ussp-01", body)
		switch {
		case err != nil:
			if len(fx.repo.notices) != 0 || len(fx.bus.published()) != 0 {
				t.Fatalf("a refused body was stored: %v", err)
			}
		case len(errs) > 0:
			t.Fatalf("accepted a body DecodeNotice refuses: %v", errs)
		default:
			n, gerr := fx.repo.Notice(context.Background(), rec.AckID)
			if gerr != nil || string(n.Payload) != string(body) || !json.Valid(n.Payload) {
				t.Fatalf("stored %q for %q (%v)", n.Payload, body, gerr)
			}
		}
	})
}

// FuzzOccurrence: the occurrence and acknowledgement decoders never
// panic, and what they accept is within its bounds.
func FuzzOccurrence(f *testing.F) {
	f.Add([]byte(occurrenceBody))
	f.Add([]byte(`{"note":"aware"}`))
	f.Add([]byte(`{"aircraft":[{"serial":1}],"manned":[null],"min_separation":{"h_m":"x"}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if in, errs := DecodeOccurrence(body); len(errs) == 0 {
			if in.Narrative == "" || len(in.Narrative) > MaxNarrativeBytes || len(in.PersonRef) > MaxPersonRefBytes ||
				len(in.Aircraft) > MaxOccurrenceItems || len(in.Manned) > MaxOccurrenceItems || in.BecameAwareAt.Before(in.OccurredAt) {
				t.Fatalf("accepted out of bounds: %+v", in)
			}
		}
		if note, fe := DecodeAcknowledge(body); fe == nil && len(note) > MaxNoteBytes {
			t.Fatal("a note past its bound")
		}
	})
}
