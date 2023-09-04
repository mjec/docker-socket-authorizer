package main

import (
	"net"
	"net/http"
	"os"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"

	"github.com/spf13/viper"
)

func main() {
	config.InitializeConfiguration()
	// ConfigureLogger() guarantees we can use slog.Error() after it's run, but no earlier.
	// However, we can't call ConfigureLogger() until we have read the config. So we save any
	// error we get reading the config, go off and run ConfigureLogger(), then log both the
	// config loading error (if any) and the logger configuration error (if any).
	// Hence these two lines MUST remain together, in this order; even though it'd be nice to
	// use if err := ...; err != nil { ... } constructs.
	load_configuration_err := config.LoadConfiguration()
	configure_logger_err := o11y.ConfigureLogger()
	// Now we can record those errors, which we do in the order in which they ocurred.
	if load_configuration_err != nil {
		var contextualLogger *slog.Logger = slog.With(slog.Any("error", load_configuration_err))
		if viper.ConfigFileUsed() == "" {
			contextualLogger = contextualLogger.With(slog.String("file", viper.ConfigFileUsed()))
		}
		if config.ConfigurationPointer == nil {
			contextualLogger.Error("Unable to load configuration file and cannot set defaults; exiting")
			os.Exit(1)
		}
		contextualLogger.Warn("Unable to load configuration file; continuing with default settings")
	}
	if configure_logger_err != nil {
		slog.Error("Logger configuration failed, continuing with defaults", slog.Any("error", configure_logger_err))
	}

	cfg := config.ConfigurationPointer

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

	if cfg.Policy.WatchDirectories {
		policyWatcher, load_configuration_err := internal.WatchPolicies()
		if load_configuration_err != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", load_configuration_err))
		}
		internal.GlobalPolicyWatcher.Store(policyWatcher)
	}

	serve_mux := http.NewServeMux()

	for path, handler := range handlers.ReflectionHandlers() {
		serve_mux.HandleFunc("/reflection/"+path, handler)
	}

	for path, handler := range handlers.ReloadHandlers() {
		serve_mux.HandleFunc("/reload/"+path, handler)
	}

	serve_mux.HandleFunc("/authorize", handlers.Authorize)

	if cfg.Authorizer.IncludesMetrics {
		serve_mux.Handle(cfg.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))
	}

	if cfg.Metrics.Listener.Type != "" && cfg.Metrics.Listener.Type != "none" {
		metrics_listener, err := net.Listen(cfg.Metrics.Listener.Type, cfg.Metrics.Listener.Address)
		if err != nil {
			slog.Error("Unable to start metrics server", slog.Any("error", err))
			os.Exit(1)
		}
		defer metrics_listener.Close()

		metrics_serve_mux := http.NewServeMux()
		metrics_serve_mux.HandleFunc(cfg.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))

		go func() {
			slog.Error("Unable to start metrics server", slog.Any("reason", http.Serve(metrics_listener, metrics_serve_mux)))
		}()
	}

	slog.Info("Server starting")

	listener, load_configuration_err := net.Listen(cfg.Authorizer.Listener.Type, cfg.Authorizer.Listener.Address)
	if load_configuration_err != nil {
		slog.Error("Unable to start server", slog.Any("error", load_configuration_err))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Error("Server shut down", slog.Any("reason", http.Serve(listener, serve_mux)))
}

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.ConfigurationPointer.Metrics.Enabled {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
