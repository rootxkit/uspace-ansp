package main

import (
	"context"
	"log/slog"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

func errWrongProcess(got string) error {
	return core.Fieldf("ANSP_PROCESS", "%q, but this binary is %s", got, process)
}

// subcommand answers `migrate ...` with a refusal: manned-adapter never
// opens PostgreSQL (CLAUDE.md rule 6), so it migrates nothing; the trees
// are migrated by `api migrate relational timeseries` (or `manned-feed
// migrate timeseries`). Exit 2 either way, so a misconfigured one-shot
// service fails visibly instead of reporting success.
func subcommand(_ context.Context, logger *slog.Logger, _ config.Config, args []string) int {
	if args[0] != "migrate" || len(args) < 2 {
		logger.Error("usage: " + process + " has no subcommand")
		return 2
	}
	logger.Error("migrate: manned-adapter never opens PostgreSQL; run `api migrate relational timeseries`",
		slog.Any("trees", args[1:]))
	return 2
}
