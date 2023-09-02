package main

import (
	"net"
	"net/http"
	"os"

	// Once we upgrade to go 1.21 this will become "log/slog"
	"golang.org/x/exp/slog"

	"github.com/fsnotify/fsnotify"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/viper"
)

func main() {
	// TODO: @CONFIG logging configuration
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	viper.SetDefault("policy.directories", []string{"./policies"})
	viper.SetDefault("policy.watch", true)
	viper.SetDefault("policy.strict", true)
	viper.SetDefault("policy.print", true)
	viper.SetDefault("reflection.enabled", true)
	viper.SetDefault("authorizer.listener.type", "unix")
	viper.SetDefault("authorizer.listener.address", "./serve.sock")
	viper.SetDefault("authorizer.listener.includes_metrics", false)
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.listener.type", "tcp")
	viper.SetDefault("metrics.listener.address", ":9100")

	viper.SetConfigName("docker-socket-authorizer")
	// viper.AddConfigPath("/etc/docker-socket-authorizer/")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		slog.Warn("Unable to locate config file; continuing with default settings", slog.Any("error", err))
		slog.Info("Writing config file, for the lulz", slog.Any("error", viper.SafeWriteConfig()))
	}

	viper.WatchConfig()

	if err := internal.LoadPolicies(); err != nil {
		slog.Error("Unable to load policies", slog.Any("error", err))
		os.Exit(1)
	}

	configurePolicyWatcher()

	if viper.GetBool("reflection.enabled") {
		for path, handler := range handlers.ReflectionHandlers() {
			http.HandleFunc("/reflection/"+path, handler)
		}
	}
	http.HandleFunc("/reload", handlers.Reload)
	http.HandleFunc("/authorize", handlers.Authorize)

	if viper.GetBool("authorizer.listener.includes_metrics") {
		http.Handle(viper.GetString("metrics.path"), promhttp.Handler())
	}

	if viper.GetString("metrics.listener.type") != "" && viper.GetString("metrics.listener.type") != "none" {
		metrics_listener, err := net.Listen(viper.GetString("metrics.listener.type"), viper.GetString("metrics.listener.address"))
		if err != nil {
			slog.Error("Unable to start metrics server", slog.Any("error", err))
			os.Exit(1)
		}
		defer metrics_listener.Close()

		mux := http.NewServeMux()
		mux.Handle(viper.GetString("metrics.path"), promhttp.Handler())

		go func() {
			slog.Error("Unable to start metrics server", slog.Any("reason", http.Serve(metrics_listener, mux)))
		}()
	}

	slog.Info("Server starting")

	listener, err := net.Listen(viper.GetString("authorizer.listener.type"), viper.GetString("authorizer.listener.address"))
	if err != nil {
		slog.Error("Unable to start server", slog.Any("error", err))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Error("Unable to start server", slog.Any("reason", http.Serve(listener, nil)))
}

func configurePolicyWatcher() {
	var (
		policy_watcher *internal.PolicyWatcher
		err            error
	)
	if viper.GetBool("policy.watch") {
		if policy_watcher, err = internal.WatchPolicies(); err != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", err))
			os.Exit(1)
		}
	}
	viper.OnConfigChange(func(e fsnotify.Event) {
		policy_watcher.Close()
		configurePolicyWatcher()
	})
}
