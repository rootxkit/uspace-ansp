package obs

import (
	"io"
	"log/slog"
	"os"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// Logger is the JSON logger of the process on stdout, at the level of
// ANSP_LOG_LEVEL, with process and instance on every line.
func Logger(cfg config.Config) *slog.Logger { return LoggerTo(os.Stdout, cfg) }

// LoggerTo is Logger writing to w.
func LoggerTo(w io.Writer, cfg config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		// config.Load refuses any other value; info is the safe reading.
		level = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h).With(slog.String("process", cfg.Process), slog.String("instance", cfg.Instance))
}
