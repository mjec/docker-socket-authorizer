package o11y

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var Metrics = struct {
	Approved        prometheus.Counter
	Denied          prometheus.Counter
	Errors          prometheus.Counter
	PolicyLoads     prometheus.Counter
	PolicyLoadTimer prometheus.Histogram
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
}
