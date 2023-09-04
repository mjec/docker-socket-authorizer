package handlers

import (
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"golang.org/x/exp/slog"

	"github.com/open-policy-agent/opa/rego"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	var contextualLogger *slog.Logger = slog.Default()
	cfg := config.ConfigurationPointer.Load()
	input, err := internal.MakeInput(r)
	if err != nil {
		contextualLogger.Error("Error making input", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}
	if cfg.Log.Input {
		// TODO: @CONFIG it'd be nice to be able to configure which fields are logged
		contextualLogger = contextualLogger.With(slog.Any("input", input))
	}

	// It's important we clone the pointer here! Otherwise we'll be racing with policy reloads
	evaluator := internal.Evaluator

	resultSet, err := evaluator.EvaluateQuery(r.Context(), rego.EvalInput(input))
	if err != nil {
		contextualLogger.Error("Error evaluating policy", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}

	if cfg.Log.DetailedResult {
		// TODO: @CONFIG it'd be nice to be able to configure which fields are logged
		contextualLogger = contextualLogger.With(slog.Any("result", resultSet[0].Bindings))
	}

	if err := evaluator.WriteToStorage(r.Context(), resultSet[0].Bindings["to_store"].(map[string]interface{})); err != nil {
		contextualLogger.Error("Error writing to storage", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}

	// NOTE: do NOT use `resultSet.Allowed()`!
	// The query is not set up for that. Always explicitly check the `ok` output.
	if resultSet[0].Bindings["ok"].(bool) {
		o11y.Metrics.Approved.Inc()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
		contextualLogger.Info("Request processed", slog.Bool("ok", true))
		return
	}

	// deny by default (in particular, in case we forgot a `return` somewhere above)
	o11y.Metrics.Denied.Inc()
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintln(w, "Forbidden")
	contextualLogger.Info("Request processed", slog.Bool("ok", false))
}
