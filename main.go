package main

import (
	"net"
	"net/http"
	"os"

	// Once we upgrade to go 1.21 this will become "log/slog"
	"golang.org/x/exp/slog"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/viper"
)

func main() {
	viper.SetDefault("policy.directories", []string{"./policies"})
	viper.SetDefault("policy.watch_directories", true)
	viper.SetDefault("policy.strict_mode", true)
	viper.SetDefault("policy.print_enabled", true)
	viper.SetDefault("reflection.enabled", true)
	viper.SetDefault("authorizer.listener.type", "unix")
	viper.SetDefault("authorizer.listener.address", "./serve.sock")
	viper.SetDefault("authorizer.listener.includes_metrics", false)
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.listener.type", "tcp")
	viper.SetDefault("metrics.listener.address", ":9100")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.input", true)
	viper.SetDefault("log.detailed_result", true)

	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/docker-socket-authorizer/")
	viper.AddConfigPath(".")

	var logger *slog.Logger
	err := viper.ReadInConfig()
	if err != nil {
		// TODO: @CONFIG output to file instead of stderr
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(logger)
		slog.Warn("Unable to locate config file; continuing with default settings", slog.Any("error", err))
	} else {
		lvl := slog.LevelInfo
		if err := lvl.UnmarshalText([]byte(viper.GetString("log.level"))); err != nil {
			// TODO: @CONFIG output to file instead of stderr
			logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			slog.SetDefault(logger)
			slog.Error("Unable to parse log level", slog.Any("error", err))
		} else {
			// TODO: @CONFIG output to file instead of stderr
			logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
			slog.SetDefault(logger)
		}
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

	if viper.GetBool("policy.watch_directories") {
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

	if viper.GetBool("authorizer.listener.includes_metrics") {
		serve_mux.Handle(viper.GetString("metrics.path"), ifMetricsEnabled(promhttp.Handler()))
	}

	if viper.GetString("metrics.listener.type") != "" && viper.GetString("metrics.listener.type") != "none" {
		metrics_listener, err := net.Listen(viper.GetString("metrics.listener.type"), viper.GetString("metrics.listener.address"))
		if err != nil {
			slog.Error("Unable to start metrics server", slog.Any("error", err))
			os.Exit(1)
		}
		defer metrics_listener.Close()

		metrics_serve_mux := http.NewServeMux()
		metrics_serve_mux.HandleFunc(viper.GetString("metrics.path"), ifMetricsEnabled(promhttp.Handler()))

		go func() {
			slog.Error("Unable to start metrics server", slog.Any("reason", http.Serve(metrics_listener, metrics_serve_mux)))
		}()
	}

	slog.Info("Server starting")

	listener, err := net.Listen(viper.GetString("authorizer.listener.type"), viper.GetString("authorizer.listener.address"))
	if err != nil {
		slog.Error("Unable to start server", slog.Any("error", err))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Error("Unable to start server", slog.Any("reason", http.Serve(listener, serve_mux)))
}

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !viper.GetBool("metrics.enabled") {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
