package o11y

import (
	"net"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal/shutdown"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"
)

var Metrics = struct {
	Approved             prometheus.Counter
	Denied               prometheus.Counter
	Errors               prometheus.Counter
	PolicyLoads          prometheus.Counter
	PolicyLoadTimer      prometheus.Histogram
	PolicyMutexWaitTimer prometheus.Histogram
}{
	Approved: promauto.NewCounter(prometheus.CounterOpts{
		Name: "docker_sock_authorizer_approved",
		Help: "The total number of approved requests",
	}),
	Denied: promauto.NewCounter(prometheus.CounterOpts{
		Name: "docker_sock_authorizer_denied",
		Help: "The total number of denied requests",
	}),
	Errors: promauto.NewCounter(prometheus.CounterOpts{
		Name: "docker_sock_authorizer_errors",
		Help: "The total number of requests resulting in an internal server error",
	}),
	PolicyLoads: promauto.NewCounter(prometheus.CounterOpts{
		Name: "docker_sock_authorizer_configuration_loads",
		Help: "The total number of times policies have been (re)loaded",
	}),
	PolicyLoadTimer: promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "docker_sock_authorizer_policy_load_seconds",
		Help: "The time it takes to load policies for the authorizer",
	}),
	PolicyMutexWaitTimer: promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "docker_sock_authorizer_policy_mutex_wait_seconds",
		Help: "The time it takes to acquire the policy mutex; always contained in policy_load time",
	}),
}

func InitializeMetrics(cfg *config.Configuration) error {
	if cfg.Metrics.Listener.Type != "" && cfg.Metrics.Listener.Type != "none" {
		metricsListener, err := net.Listen(cfg.Metrics.Listener.Type, cfg.Metrics.Listener.Address)
		if err != nil {
			return err
		}
		defer shutdown.OnShutdown("metrics", func() {
			metricsListener.Close()
		})

		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc(
			cfg.Metrics.Path,
			func(w http.ResponseWriter, r *http.Request) {
				if !config.ConfigurationPointer.Load().Metrics.Enabled {
					http.NotFound(w, r)
					return
				}
				promhttp.Handler().ServeHTTP(w, r)
			},
		)

		go func() {
			shutdownErr := http.Serve(metricsListener, metricsMux)
			_ = shutdown.Shutdown("metrics server error", slog.LevelError, slog.With("error", shutdownErr))
		}()
	}

	return nil
}
