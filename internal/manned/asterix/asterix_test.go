package asterix_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/asterix"
)

// The stub fails loudly and permanently, naming the deferral (gap 12).
func TestCat021RefusesNamingTheDeferral(t *testing.T) {
	var a asterix.Cat021
	err := a.Run(context.Background(), nil)
	if a.Kind() != adapter.KindASTERIXCat021 || !errors.Is(err, adapter.ErrDeferred) || !errors.Is(err, adapter.ErrPermanent) ||
		!strings.Contains(err.Error(), "gap 12") {
		t.Fatal(err)
	}
}
