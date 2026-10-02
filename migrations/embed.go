// Package migrations embeds the two goose trees (CLAUDE.md rule 6).
// They are applied only by the migrate subcommand (internal/store
// Migrate), each to its own database with its own version table
// (goose_db_version_relational, goose_db_version_timeseries); the trees
// are never merged.
package migrations

import "embed"

// Relational is the PostgreSQL + PostGIS tree.
//
//go:embed relational/*.sql
var Relational embed.FS

// Timeseries is the TimescaleDB tree.
//
//go:embed timeseries/*.sql
var Timeseries embed.FS
