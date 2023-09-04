package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal"
	"golang.org/x/exp/slog"
)

func ReflectionHandlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"input":                 ifEnabled(inputHandler),
		"query":                 ifEnabled(queryHandler),
		"meta-policy":           ifEnabled(metaPolicyHandler),
		"configuration":         ifEnabled(configurationHandler),
		"default-configuration": ifEnabled(defaultConfigurationHandler),
	}
}

func ifEnabled(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.ConfigurationPointer.Load().Reflection.Enabled {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	}
}

func inputHandler(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		slog.Error("Unable to construct input (likely a bug)", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintln(w, "Unable to construct input")
		return
	}
	j, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		slog.Error("Unable to marshal input to JSON (likely a bug)", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintln(w, "Unable to marshal input")
		return
	}
	w.Header().Add("content-type", "application/json")
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

func configurationHandler(w http.ResponseWriter, r *http.Request) {
	j, err := json.MarshalIndent(config.ConfigurationPointer, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintln(w, "Unable to marshal configuration")
		slog.Error("Unable to marshal configuration to JSON (likely a bug)", slog.Any("error", err))
		return
	}
	w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, "%s\n", j)
}

func defaultConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	j, err := json.MarshalIndent(config.DefaultConfiguration(), "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintln(w, "Unable to marshal default configuration")
		slog.Error("Unable to marshal default configuration to JSON (likely a bug)", slog.Any("error", err))
		return
	}
	w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, "%s\n", j)
}
