package main

import (
	"os"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/authsvr"
	"github.com/mjec/docker-socket-authorizer/internal/lifecycle"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/mjec/docker-socket-authorizer/internal/shutdown"
	"golang.org/x/exp/slog"
)

func main() {
	cfg := lifecycle.Bootstrap()
	lifecycle.InitializeSignalHandler(&cfg)

	if err := internal.InitializePolicies(&cfg); err != nil {
		slog.Error("Unable to initialize policies", slog.Any("error", err))
		os.Exit(1)
	}

	if err := o11y.InitializeMetrics(&cfg); err != nil {
		slog.Error("Unable to initialize metrics", slog.Any("error", err))
		os.Exit(1)
	}

	if err := authsvr.InitializeAuthServer(&cfg); err != nil {
		slog.Error("Unable to initialize authorization server", slog.Any("error", err))
		os.Exit(1)
	}

	shutdown.WaitForShutdown()
}
