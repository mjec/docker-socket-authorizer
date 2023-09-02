package main

import (
	"net/http"
	"os"

	// Once we upgrade to go 1.21 this will become "log/slog"
	"golang.org/x/exp/slog"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// TODO: @CONFIG logging configuration
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := internal.LoadPolicies(); err != nil {
		slog.Error("Unable to load policies", slog.Any("error", err))
		os.Exit(1)
	}
	// TODO: @CONFIG determine whether to watch files
	go internal.WatchPolicies()

	for path, handler := range handlers.ReflectionHandlers() {
		http.HandleFunc("/reflection/"+path, handler)
	}
	http.HandleFunc("/reload", handlers.Reload)
	http.HandleFunc("/authorize", handlers.Authorize)
	http.Handle("/metrics", promhttp.Handler())

	slog.Info("Server started")
	slog.Error("Shutting down", slog.Any("reason", http.ListenAndServe(":8080", nil))) // TODO: @CONFIG port
}
