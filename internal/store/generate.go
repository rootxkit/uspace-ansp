package store

// sqlc v1.31.1, pinned (docs/PLAN.md section 4: a tool run with go run,
// not a module dependency). It reads ../../sqlc.yaml and writes
// internal/store/relational and internal/store/timeseries.
//go:generate go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate -f ../../sqlc.yaml
