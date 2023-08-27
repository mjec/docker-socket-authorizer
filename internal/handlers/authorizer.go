package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"

	"github.com/open-policy-agent/opa/rego"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		log.Printf("Error making input: %s\n", err)
		// TODO: should this return a 500 instead?
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}

	// It's important we clone the pointer here! Otherwise we'll be racing with policy reloads
	evaluator := internal.Evaluator

	result_set, err := evaluator.EvaluateQuery(r.Context(), rego.EvalInput(input))
	if err != nil {
		log.Printf("Error applying policy: %s\n", err)
		// TODO: should this return a 500 instead?
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}

	debug_info, _ := json.Marshal(map[string]interface{}{
		"input":  input,
		"result": result_set[0].Bindings,
	})

	if err := evaluator.WriteToStorage(r.Context(), result_set[0].Bindings["to_store"].(map[string]interface{})); err != nil {
		log.Printf("Error writing to storage: %s\n", err)
		// TODO: should this return a 500 instead?
		// TODO: @CONFIG - should we deny the request if we can't write to storage?
		o11y.Metrics.Denied.Inc()
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}

	// NOTE: do NOT use `result_set.Allowed()`!
	// The query is not set up for that. Always explicitly check the `ok` output.
	if result_set[0].Bindings["ok"].(bool) {
		o11y.Metrics.Approved.Inc()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
		log.Printf("Request approved: %s\n", debug_info)
		return
	}

	// deny by default (in particular, in case we forgot a `return` somewhere above)
	log.Printf("Request denied: %s\n", debug_info)
	o11y.Metrics.Denied.Inc()
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintln(w, "Forbidden")
}
