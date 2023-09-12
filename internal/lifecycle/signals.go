package lifecycle

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal/shutdown"
	"golang.org/x/exp/slog"
)

func InitializeSignalHandler(cfg *config.Configuration) {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	go func() {
		signal := <-signalChannel
		switch signal {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			_ = shutdown.Shutdown("signal", slog.LevelInfo, slog.With(slog.String("signal", signal.String())))
		case syscall.SIGHUP:
			// This means doing everything we do in reloadConfiguration
			slog.Info("SIGHUP is not currently supported but eventually may cause config reloads")
		}
	}()
}
