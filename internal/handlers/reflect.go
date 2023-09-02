package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

func ReflectionHandlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"input":       ifEnabled(inputHandler),
		"query":       ifEnabled(queryHandler),
		"meta-policy": ifEnabled(metaPolicyHandler),
	}
}

func ifEnabled(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !viper.GetBool("reflection.enabled") {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	}
}

func inputHandler(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		slog.Error("Error making input", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to construct input")
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

func queryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	fmt.Fprintf(w, "%s", internal.QUERY)
}

func metaPolicyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	fmt.Fprintf(w, "%s", internal.META_POLICY)
}
