package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
	"golang.org/x/exp/slog"
)

func Reflect(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		slog.Error("Error making input", slog.Any("error", err))
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Invalid request")
		return
	}
	w.Header().Add("content-type", "application/json")
	j, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to marshal input")
		slog.Error("Unable to marshal input to JSON", slog.Any("error", err))
		return
	}
	fmt.Fprintf(w, "%s\n", j)
}
