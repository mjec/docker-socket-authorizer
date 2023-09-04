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
	cfg, loadConfigurationErr := config.LoadConfiguration()
	configureLoggerErr := o11y.ConfigureLogger()
	// Now we can record those errors, which we do in the order in which they ocurred.
	if loadConfigurationErr != nil {
		var contextualLogger *slog.Logger = slog.With(slog.Any("error", loadConfigurationErr))
		if viper.ConfigFileUsed() == "" {
			contextualLogger = contextualLogger.With(slog.String("file", viper.ConfigFileUsed()))
		}
		if config.ConfigurationPointer == nil {
			contextualLogger.Error("Unable to load configuration file and cannot set defaults; exiting")
			os.Exit(1)
		}
		contextualLogger.Warn("Unable to load configuration file; continuing with default settings")
	}
	if configureLoggerErr != nil {
		slog.Error("Logger configuration failed, continuing with defaults", slog.Any("error", configureLoggerErr))
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

	if cfg.Policy.WatchDirectories {
		policyWatcher, watchPoliciesErr := internal.WatchPolicies()
		if watchPoliciesErr != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", watchPoliciesErr))
		}
		internal.GlobalPolicyWatcher.Store(policyWatcher)
	}

	authorizerMux := http.NewServeMux()

	for path, handler := range handlers.ReflectionHandlers() {
		authorizerMux.HandleFunc("/reflection/"+path, handler)
	}

	for path, handler := range handlers.ReloadHandlers() {
		authorizerMux.HandleFunc("/reload/"+path, handler)
	}

	authorizerMux.HandleFunc("/authorize", handlers.Authorize)

	if cfg.Authorizer.IncludesMetrics {
		authorizerMux.Handle(cfg.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))
	}

	if cfg.Metrics.Listener.Type != "" && cfg.Metrics.Listener.Type != "none" {
		metricsListener, err := net.Listen(cfg.Metrics.Listener.Type, cfg.Metrics.Listener.Address)
		if err != nil {
			slog.Error("Unable to start metrics server", slog.Any("error", err))
			os.Exit(1)
		}
		defer metricsListener.Close()

		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc(cfg.Metrics.Path, ifMetricsEnabled(promhttp.Handler()))

		go func() {
			slog.Error("Unable to start metrics server", slog.Any("reason", http.Serve(metricsListener, metricsMux)))
		}()
	}

	slog.Info("Server starting")

	listener, loadConfigurationErr := net.Listen(cfg.Authorizer.Listener.Type, cfg.Authorizer.Listener.Address)
	if loadConfigurationErr != nil {
		slog.Error("Unable to start server", slog.Any("error", loadConfigurationErr))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Error("Server shut down", slog.Any("reason", http.Serve(listener, authorizerMux)))
}

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.ConfigurationPointer.Load().Metrics.Enabled {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
