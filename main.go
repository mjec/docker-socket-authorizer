package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/mjec/docker-socket-authorizer/internal/shutdown"
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
	if loadConfigurationErr != nil {
		if !config.ConfigurationPointer.CompareAndSwap(nil, config.DefaultConfiguration()) {
			panic(fmt.Errorf("unable to set configuration to default (likely a bug) after failing to load configuration: %w", loadConfigurationErr))
		}
	}
	configureLoggerErr := o11y.ConfigureLogger()
	// Now we can record those errors, which we do in the order in which they ocurred.
	if loadConfigurationErr != nil {
		var contextualLogger *slog.Logger = slog.With(slog.Any("error", loadConfigurationErr))
		if viper.ConfigFileUsed() == "" {
			contextualLogger = contextualLogger.With(slog.String("file", viper.ConfigFileUsed()))
		}
		contextualLogger.Warn("Unable to load configuration file; continuing with defaults", slog.Any("error", loadConfigurationErr))
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

	initializeSignalHandler(cfg)

	if err := internal.InitializePolicies(cfg); err != nil {
		slog.Error("Unable to initialize policies", slog.Any("error", err))
		os.Exit(1)
	}

	if err := o11y.InitializeMetrics(cfg); err != nil {
		slog.Error("Unable to initialize metrics", slog.Any("error", err))
		os.Exit(1)
	}

	if err := initializeAuthServer(cfg); err != nil {
		slog.Error("Unable to initialize authorization server", slog.Any("error", err))
		os.Exit(1)
	}

	shutdown.Wait()
}

func initializeAuthServer(cfg *config.Configuration) error {
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

	listener, err := net.Listen(cfg.Authorizer.Listener.Type, cfg.Authorizer.Listener.Address)
	if err != nil {
		return err
	}

	defer shutdown.OnShutdown("auth server", func() {
		listener.Close()
	})

	go func() {
		shutdownErr := http.Serve(listener, authorizerMux)
		_ = shutdown.Shutdown("authorization server error", slog.LevelError, slog.With(slog.Any("error", shutdownErr)))
	}()

	return nil
}

func initializeSignalHandler(cfg *config.Configuration) {
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

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.ConfigurationPointer.Load().Metrics.Enabled {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
