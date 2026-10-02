// Package asterix is the ASTERIX CAT021 adapter, deferred until the
// ANSP's data-release agreement names the format (docs/PLAN.md section
// 15 gap 12). Its Run refuses at once with adapter.ErrDeferred, which is
// permanent, so a deployment configured with it fails loudly instead of
// publishing nothing in silence. No ASTERIX item is written from memory.
package asterix
