package handlers

import (
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"

	"github.com/open-policy-agent/opa/rego"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		slog.Error("Error making input", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}
	var contextualLogger *slog.Logger
	if viper.GetBool("log.input") {
		// TODO: @CONFIG it'd be nice to be able to configure which fields are logged
		contextualLogger = slog.With(slog.Any("input", input))
	} else {
		contextualLogger = slog.With()
	}

	// It's important we clone the pointer here! Otherwise we'll be racing with policy reloads
	evaluator := internal.Evaluator

	result_set, err := evaluator.EvaluateQuery(r.Context(), rego.EvalInput(input))
	if err != nil {
		contextualLogger.Error("Error evaluating policy", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}

	if viper.GetBool("log.detailed_result") {
		// TODO: @CONFIG it'd be nice to be able to configure which fields are logged
		contextualLogger = contextualLogger.With(slog.Any("result", result_set[0].Bindings))
	} else {
		contextualLogger = slog.With()
	}

	if err := evaluator.WriteToStorage(r.Context(), result_set[0].Bindings["to_store"].(map[string]interface{})); err != nil {
		contextualLogger.Error("Error writing to storage", slog.Any("error", err))
		o11y.Metrics.Errors.Inc()
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Internal Server Error")
		return
	}

	// NOTE: do NOT use `result_set.Allowed()`!
	// The query is not set up for that. Always explicitly check the `ok` output.
	if result_set[0].Bindings["ok"].(bool) {
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
