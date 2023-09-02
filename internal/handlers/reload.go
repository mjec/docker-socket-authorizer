package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/cfg"
	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"golang.org/x/exp/slog"
)

func Reload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Method not allowed (use POST)")
		return
	}

	results := struct {
		Configuration string `json:"configuration"`
		Policies      string `json:"policies"`
	}{
		Configuration: "Did not attempt to reload",
		Policies:      "Did not attempt to reload",
	}
	any_errors := false

	if cfg.Configuration.Reload.Configuration {
		if err := cfg.LoadConfiguration(); err != nil {
			results.Configuration = fmt.Sprintf("Unable to reload config: %s", err)
			any_errors = true
		} else {
			o11y.ConfigureLogger()
			results.Configuration = "Reloaded OK (NOTE: some configuration values require a restart to change)"
		}

		// If we have a policy watcher but our config is not to, that means it changed. We should shut down the watcher.
		if internal.GlobalPolicyWatcher != nil && !cfg.Configuration.Policy.WatchDirectories {
			// This cannot be consolidated with the Close() in the next block, because we need to wait for the new watcher to be
			// established before we close the old one. Otherwise we risk a (brief) period where changes to policies do not
			// result in a policy reload, even though the `policy.watch_directories` configuration value did not change.
			internal.GlobalPolicyWatcher.Close()
			internal.GlobalPolicyWatcher = nil
		}

		if cfg.Configuration.Policy.WatchDirectories {
			if policyWatcher, err := internal.WatchPolicies(); err != nil {
				slog.Error("Unable to establish policy watcher", slog.Any("error", err))
			} else {
				// If we're here, that means we want to watch directories, whether or not that has changed. Restart the
				// watcher to be safe. But don't shut down the existing watcher (if it exists) until the new one is up
				// successfully. Otherwise we risk a (brief) period where changes to policies do not result in a policy
				// reload, even though the `policy.watch_directories` configuration value did not change.
				if internal.GlobalPolicyWatcher != nil {
					internal.GlobalPolicyWatcher.Close()
					internal.GlobalPolicyWatcher = nil
				}
				internal.GlobalPolicyWatcher = policyWatcher
			}
		}
	}

	if cfg.Configuration.Reload.Policies {
		if err := internal.LoadPolicies(); err != nil {
			results.Policies = fmt.Sprintf("Unable to reload policies: %s", err)
			any_errors = true
		} else {
			results.Policies = "Reloaded OK"
		}
	}

	if any_errors {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	j, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("content-type", "text/plain")
		fmt.Fprintf(w, "Unable to generate JSON response: %s\n%v", err, results)
		return
	}

	w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, "%s\n", j)
}
