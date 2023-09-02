package o11y

import (
	"os"

	"github.com/mjec/docker-socket-authorizer/cfg"
	"golang.org/x/exp/slog"
)

var logger *slog.Logger

func ConfigureLogger() {
	lvl := slog.LevelInfo
	err := lvl.UnmarshalText([]byte(cfg.Configuration.Log.Level))

	logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)

	if err != nil {
		slog.Error("Unable to parse log configuration log level", slog.String("level", cfg.Configuration.Log.Level), slog.Any("error", err))
	}
}
