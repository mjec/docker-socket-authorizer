package handlers

import (
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
)

func Reload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Method not allowed (use POST)")
		return
	}

	if err := internal.LoadPolicies(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error loading policies: %s\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
