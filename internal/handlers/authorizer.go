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
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}

	result_set, err := internal.Authorizer.Eval(r.Context(), rego.EvalInput(input))
	if err != nil {
		log.Printf("Error applying policy: %s\n", err)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}

	debug_info, _ := json.Marshal(map[string]interface{}{
		"input":  input,
		"result": result_set[0].Bindings,
	})

	// NOTE: do NOT use `result_set.Allowed()`!
	// The query is not set up for that. Always explicitly check the `ok` output.
	if result_set[0].Bindings["ok"] == true {
		o11y.Metrics.Approved.Inc()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
		log.Printf("Request approved: %s\n", debug_info)
		return
	}

	o11y.Metrics.Denied.Inc()
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintln(w, "Forbidden")
	log.Printf("Request denied: %s\n", debug_info)
}
