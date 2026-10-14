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

// The trees this binary migrates: both, for the one-shot compose
// `migrate` service (CLAUDE.md rule 6; two trees, never merged).
var trees = []string{"relational", "timeseries"}

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
		if name == store.TreeTimeseries.Name && !applyPolicies(ctx, logger, cfg, dsn) {
			return 1
		}
	}
	return 0
}

// applyPolicies sets the timeseries tree's retention and compression
// jobs to the configuration (ANSP_TIMESERIES_RETENTION_DAYS,
// ANSP_TIMESERIES_COMPRESS_AFTER_DAYS) and says what it changed, or that
// nothing needed to change. False when they could not be set.
func applyPolicies(ctx context.Context, logger *slog.Logger, cfg config.Config, dsn string) bool {
	p := store.TimeseriesPolicies{RetentionDays: cfg.TimeseriesRetentionDays, CompressAfterDays: cfg.TimeseriesCompressAfterDays}
	changes, err := store.ApplyTimeseriesPolicies(ctx, dsn, p)
	if err != nil {
		logger.Error("migrate: timeseries policies not set", slog.String("error", err.Error()))
		return false
	}
	for _, c := range changes {
		logger.Info("migrate: timeseries policy set", slog.String("table", c.Table), slog.String("policy", c.Policy),
			slog.String("from", c.From), slog.String("to", c.To))
	}
	logger.Info("migrate: timeseries policies current", slog.Int("retention_days", p.RetentionDays),
		slog.Int("compress_after_days", p.CompressAfterDays), slog.Int("changed", len(changes)))
	return true
}

// treeDSN is the variable naming tree's database and its value in cfg.
func treeDSN(cfg config.Config, tree string) (variable, dsn string) {
	if tree == store.TreeRelational.Name {
		return "ANSP_RELATIONAL_DSN", cfg.RelationalDSN
	}
	return "ANSP_TIMESERIES_DSN", cfg.TimeseriesDSN
}
