package main

import (
	"net"
	"net/http"
	"os"

	"github.com/mjec/docker-socket-authorizer/cfg"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"

	"github.com/spf13/viper"
)

func main() {
	cfg.InitializeConfiguration()
	err := cfg.LoadConfiguration()
	o11y.ConfigureLogger()
	if err != nil {
		var contextualLogger *slog.Logger = slog.With(slog.Any("error", err))
		if viper.ConfigFileUsed() == "" {
			contextualLogger = contextualLogger.With(slog.String("file", viper.ConfigFileUsed()))
		}
		contextualLogger.Warn("Unable to load configuration file; continuing with default settings")
	}

	// Config cannot be gracefully reloaded; sorry.
	// The problem is we need to do things like open sockets with information contained in config, and there's no easy way to reload gracefully.
	// We could stop using net.http paths and create a handler instead, but we still need to manage the complexity of setting up and tearing down
	// paths, or at least replacing the handler methods. We can't hand off the socket reliably without introducing a lot of complexity; and closing
	// the socket seems undesirable. Thus, no config reloading. Restart when you want to change things, and it's up to you to figure out how to
	// manage the downtime.

	if err := internal.LoadPolicies(); err != nil {
		slog.Error("Unable to load policies", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.Configuration.Policy.WatchDirectories {
		if internal.GlobalPolicyWatcher, err = internal.WatchPolicies(); err != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", err))
		}
	}

	serve_mux := http.NewServeMux()

	for path, handler := range handlers.ReflectionHandlers() {
		serve_mux.HandleFunc("/reflection/"+path, handler)
	}
	serve_mux.HandleFunc("/reload", handlers.Reload)
	serve_mux.HandleFunc("/authorize", handlers.Authorize)

	if cfg.Configuration.Authorizer.IncludesMetrics {
		serve_mux.Handle(cfg.Configuration.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))
	}

	if cfg.Configuration.Metrics.Listener.Type != "" && cfg.Configuration.Metrics.Listener.Type != "none" {
		metrics_listener, err := net.Listen(cfg.Configuration.Metrics.Listener.Type, cfg.Configuration.Metrics.Listener.Address)
		if err != nil {
			slog.Error("Unable to start metrics server", slog.Any("error", err))
			os.Exit(1)
		}
		defer metrics_listener.Close()

		metrics_serve_mux := http.NewServeMux()
		metrics_serve_mux.HandleFunc(cfg.Configuration.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))

		go func() {
			slog.Error("Unable to start metrics server", slog.Any("reason", http.Serve(metrics_listener, metrics_serve_mux)))
		}()
	}

	slog.Info("Server starting")

	listener, err := net.Listen(cfg.Configuration.Authorizer.Listener.Type, cfg.Configuration.Authorizer.Listener.Address)
	if err != nil {
		slog.Error("Unable to start server", slog.Any("error", err))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Error("Server shut down", slog.Any("reason", http.Serve(listener, serve_mux)))
}

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.Configuration.Metrics.Enabled {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
