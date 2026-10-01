package main

import (
	"log/slog"
	"slices"

	"github.com/rootxkit/uspace-core/core"
)

// The two migration trees (CLAUDE.md rule 6), never merged.
var trees = []string{"relational", "timeseries"}

func errWrongProcess(got string) error {
	return core.Fieldf("ANSP_PROCESS", "%q, but this binary is %s", got, process)
}

// subcommand runs `migrate <relational|timeseries>...`, the only
// subcommand. No long-running process migrates at start (M36): the
// compose `migrate` service runs this once and the services wait for it.
func subcommand(logger *slog.Logger, args []string) int {
	if args[0] != "migrate" || len(args) < 2 {
		logger.Error("usage: " + process + " [migrate <relational|timeseries>...]")
		return 2
	}
	for _, tree := range args[1:] {
		if !slices.Contains(trees, tree) {
			logger.Error("migrate: unknown tree; the trees are relational and timeseries", slog.String("tree", tree))
			return 2
		}
	}
	for _, tree := range args[1:] {
		// WP-1 embeds the goose trees and applies them here.
		logger.Warn("migrate: no migrations are embedded until WP-1; nothing applied", slog.String("tree", tree))
	}
	return 0
}
