package main

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// The tree this binary migrates: the hypertables it alone writes
// (`manned-feed migrate timeseries`; CLAUDE.md rule 6). The relational
// tree is api's.
var trees = []string{"timeseries"}

func errWrongProcess(got string) error {
	return core.Fieldf("ANSP_PROCESS", "%q, but this binary is %s", got, process)
}

// subcommand runs `migrate <tree>...`, the only subcommand: each tree
// against its own database (ANSP_RELATIONAL_DSN, ANSP_TIMESERIES_DSN),
// in the order given. No long-running process migrates at start (M36):
// the compose `migrate` service runs this once and the services wait for
// it. 0 when every tree is current, 1 when a migration failed, 2 on a
// usage or configuration error.
func subcommand(ctx context.Context, logger *slog.Logger, cfg config.Config, args []string) int {
	if args[0] != "migrate" || len(args) < 2 {
		logger.Error("usage: " + process + " [migrate <" + strings.Join(trees, "|") + ">...]")
		return 2
	}
	for _, name := range args[1:] {
		if !slices.Contains(trees, name) {
			logger.Error("migrate: unknown tree; this binary migrates "+strings.Join(trees, " and "), slog.String("tree", name))
			return 2
		}
		if _, dsn := treeDSN(cfg, name); dsn == "" {
			variable, _ := treeDSN(config.Config{}, name)
			logger.Error("migrate: no database for the tree", slog.String("tree", name), slog.String("variable", variable))
			return 2
		}
	}
	for _, name := range args[1:] {
		tree, _ := store.TreeByName(name)
		_, dsn := treeDSN(cfg, name)
		res, err := store.Migrate(ctx, dsn, tree)
		if err != nil {
			logger.Error("migrate: failed", slog.String("tree", name), slog.Int64("from_version", res.From),
				slog.Int("applied", res.Applied), slog.String("error", err.Error()))
			return 1
		}
		logger.Info("migrate: tree current", slog.String("tree", name), slog.Int64("from_version", res.From),
			slog.Int64("version", res.To), slog.Int("applied", res.Applied))
	}
	return 0
}

// treeDSN is the variable naming tree's database and its value in cfg.
func treeDSN(cfg config.Config, tree string) (variable, dsn string) {
	if tree == store.TreeRelational.Name {
		return "ANSP_RELATIONAL_DSN", cfg.RelationalDSN
	}
	return "ANSP_TIMESERIES_DSN", cfg.TimeseriesDSN
}
