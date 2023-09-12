package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"golang.org/x/exp/slog"
)

func ReloadHandlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"configuration":   ifEnabledAndPost(func(cfg *config.Configuration) bool { return cfg.Reload.Configuration }, reloadConfiguration),
		"policies":        ifEnabledAndPost(func(cfg *config.Configuration) bool { return cfg.Reload.Policies }, reloadPolicies),
		"reopen-log-file": ifEnabledAndPost(func(cfg *config.Configuration) bool { return cfg.Reload.ReopenLogFile }, reopenLogFile),
	}
}

// This taking isEnabled as a function is necessary to check the value of the configuration at the time of the request.
func ifEnabledAndPost(isEnabled func(cfg *config.Configuration) bool, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isEnabled(config.ConfigurationPointer.Load()) {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintln(w, "Method not allowed (use POST)")
			return
		}
		handler(w, r)
	}
}

func reloadConfiguration(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadConfiguration()
	if err != nil {
		slog.Warn("Unable to reload config", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		j, jsonErr := json.MarshalIndent(struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}{
			Error:  "Unable to reload configuration",
			Reason: err.Error(),
		}, "", "  ")
		if jsonErr != nil {
			w.Header().Add("content-type", "text/plain")
			fmt.Fprintf(w, "Unable to reload config: %s\nUnable to generate JSON response: %s\n", err, jsonErr)
			return
		}
		w.Header().Add("content-type", "text/json")
		fmt.Fprintf(w, "%s\n", j)
		return
	}

	// We have a good reload!
	// Now update the things that rely on config. So far that means:
	// - reconfigure the logger
	// - restart the policy watcher
	// At some point it might be nice to consolidate this into something in config/configuration.go

	// First, some general setup for the rest of this method
	results := struct {
		Configuration    string `json:"configuration"`
		OldPolicyWatcher string `json:"old_policy_watcher"`
		NewPolicyWatcher string `json:"new_policy_watcher"`
		Logger           string `json:"logger"`
	}{
		Configuration:    "Reloaded OK (NOTE: some configuration values require a restart to change)",
		OldPolicyWatcher: "Did not attempt to stop",
		NewPolicyWatcher: "Did not attempt to start",
		Logger:           "Did not attempt to reopen",
	}

	// We are always OK as soon as the ConfigurationPointer is updated
	w.WriteHeader(http.StatusOK)

	// ConfigureLogger is thread safe
	if err := o11y.ConfigureLogger(); err != nil {
		results.Logger = fmt.Sprintf("Unable to reopen log file: %s", err)
		slog.Error("Unable to reopen log file", slog.Any("error", err))
	} else {
		results.Logger = "Reopened OK"
	}

	// GlobalPolicyWatcher is an atomic pointer which we update with CAS, making this operation thread safe
	originalPolicyWatcher := internal.GlobalPolicyWatcher.Load()
	// If we have a policy watcher but our config is not to, that means it changed. We should shut down the watcher.
	if originalPolicyWatcher != nil && !cfg.Policy.WatchDirectories {
		originalPolicyWatcher.Close()
		results.OldPolicyWatcher = "Stopped OK (because policy.watch_directories changed)"
		// We don't really care if the following CAS fails; if someone else has already updated the GlobalPolicyWatcher
		// then leave that value be. We only care about closing out originalPolicyWatcher and setting it to nil from
		// that value specifically.
		_ = internal.GlobalPolicyWatcher.CompareAndSwap(originalPolicyWatcher, nil)
	}

	if cfg.Policy.WatchDirectories {
		if policyWatcher, err := internal.WatchPolicies(); err != nil {
			results.NewPolicyWatcher = fmt.Sprintf("Unable to establish policy watcher: %s", err)
			slog.Error("Unable to establish policy watcher", slog.Any("error", err))
		} else {
			// If we're here, that means we want to watch directories, whether or not that has changed, and the
			// new policyWatcher is up and running. We restart the watcher to be safe, but don't shut down the
			// previous watcher (if it exists) until the new one is up successfully. Otherwise we risk a (brief)
			// period where changes to policies do not result in a policy reload, even if the
			// `policy.watch_directories` configuration value did not change.
			// We rely on the fact that Close() is idempotent.
			if originalPolicyWatcher != nil {
				originalPolicyWatcher.Close()
				results.OldPolicyWatcher = "Stopped OK (restarting because we are watching policy directories)"
			}
			if internal.GlobalPolicyWatcher.CompareAndSwap(originalPolicyWatcher, policyWatcher) {
				results.NewPolicyWatcher = "Started OK"
			} else {
				// Someone else beat us to the punch; discard this policy watcher, which has never been
				// available to anyone else.
				policyWatcher.Close()
				results.NewPolicyWatcher = "Discarded OK (because someone else already updated the policy watcher again while ours was starting)"
			}
		}
	}

	j, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintf(w, "Unable to generate JSON response: %s\n%v", err, results)
		return
	}

	w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, "%s\n", j)
}

func reloadPolicies(w http.ResponseWriter, r *http.Request) {
	if err := internal.LoadPolicies(); err != nil {
		slog.Warn("Unable to reload policies", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintf(w, "Unable to reload policies: %s\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("content-type", "text/plain")
	fmt.Fprintln(w, "Reloaded OK")
}

func reopenLogFile(w http.ResponseWriter, r *http.Request) {
	if err := o11y.ConfigureLogger(); err != nil {
		slog.Warn("Unable to reopen log file", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintf(w, "Unable to reopen log file: %s\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("content-type", "text/plain")
	fmt.Fprintln(w, "Reloaded OK")
}
