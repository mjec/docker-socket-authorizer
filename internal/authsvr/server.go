package authsvr

import (
	"net"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal/authsvr/handlers"
	"github.com/mjec/docker-socket-authorizer/internal/shutdown"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"
)

func InitializeAuthServer(cfg *config.Configuration) error {
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

func ifMetricsEnabled(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.ConfigurationPointer.Load().Metrics.Enabled {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
