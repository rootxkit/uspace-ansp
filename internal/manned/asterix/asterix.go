package asterix

import (
	"context"
	"fmt"

	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

// Cat021 is the ASTERIX CAT021 adapter, deferred: which surveillance
// formats the ANSP can hand over is open with the owner
// (docs/PLAN.md section 15 gap 12; spec 08 Q3, Q14), and no ASTERIX
// field is written here from memory (E-03).
type Cat021 struct{}

// Kind is asterix_cat021.
func (Cat021) Kind() string { return adapter.KindASTERIXCat021 }

// Run refuses at once, naming the deferral, so a deployment configured
// with this kind fails loudly instead of publishing nothing in silence.
func (Cat021) Run(context.Context, adapter.Sink) error {
	return fmt.Errorf("%w: asterix_cat021 is deferred until the data-release agreement names the format "+
		"(docs/PLAN.md section 15 gap 12); configure replay, dump1090_sbs or dump1090_json", adapter.ErrDeferred)
}
