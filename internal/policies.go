package internal

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/exp/slog"
)

var (
	Evaluator           atomic.Pointer[RegoEvaluator] = atomic.Pointer[RegoEvaluator]{}
	GlobalPolicyWatcher atomic.Pointer[PolicyWatcher] = atomic.Pointer[PolicyWatcher]{}
	loadPoliciesMutex   *sync.Mutex                   = &sync.Mutex{}
)

// NOTE: if you are changing the QUERY or META_POLICY, please ensure HACKING.md is also updated to reflect your changes.

// This query produces the following outputs that govern program behavior:
// - ok: boolean, true if and only if the request is approved
// - meta_policy_ok: boolean, true if and only if the meta-policy passes
// - all_policies: []string, a list of the names of policies that are loaded under the `docker_socket_authorizer` namespace
// - to_store: map[string]interface{}, a map from policy to data to store for that policy
// This query also produces the following outputs that are used for logging:
// - denies: map[string]string, a map from policy to message for each policy with a result of "deny"
// - allows: map[string]string, a map from policy to message for each policy with a result of "allow"
// - skips: map[string]string, a map from policy to message for each policy with a result of "skip"
// - invalid_policies: []string, a list of policy names that do not produce a valid `result` and `message`
// - invalid_storage: []string, a list of policy names that do not produce a valid `to_store` object
const QUERY = `
denies = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "deny"}
allows = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "allow"}
skips = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "skip"}

invalid_policies = data.docker_socket_meta_policy.invalid_policies
invalid_storage = data.docker_socket_meta_policy.invalid_storage
all_policies = data.docker_socket_meta_policy.all_policies
meta_policy_ok = data.docker_socket_meta_policy.ok

to_store = {policy: data.docker_socket_authorizer[policy].to_store | true}

ok_conditions = {
	"meta-policy passes": meta_policy_ok,
	"no invalid policies": count(invalid_policies) == 0,
	"no invalid storages": count(invalid_storage) == 0,
	"no denials": count(denies) == 0,
	"at least one allow": count(allows) > 0,
}
ok = count({x | ok_conditions[x] == true}) == count(ok_conditions)

# Baseline legitimacy check: all policies should have a result of allow, deny or skip; or be invalid.
# We explicitly construct the list of policies, rather than relying on all_policies, which is calculated by the meta-policy.
count({policy | data.docker_socket_authorizer[policy]}) == count(denies) + count(allows) + count(skips) + count(invalid_policies)
`

// This policy produces the following outputs that govern program behavior:
// ok: boolean, true if and only if the meta-policy passes
// all_policies: []string, a list of the names of policies that are loaded under the `docker_socket_authorizer` namespace
// invalid_policies: []string, a list of policy names that do not produce a valid `result` and `message`
// invalid_storage: []string, a list of policy names that do not produce a valid `to_store` object
const META_POLICY = `
package docker_socket_meta_policy

default ok := false

all_policies = { policy | data.docker_socket_authorizer[policy] }
allow_policies = { policy |
	data.docker_socket_authorizer[policy].message != ""
	data.docker_socket_authorizer[policy].result == "allow"
}
skip_policies = { policy |
	data.docker_socket_authorizer[policy].message != ""
	data.docker_socket_authorizer[policy].result == "skip"
}
deny_policies = { policy |
	data.docker_socket_authorizer[policy].message != ""
	data.docker_socket_authorizer[policy].result == "deny"
}
ok_policies = union({allow_policies, skip_policies, deny_policies})

invalid_storage = {policy |
	data.docker_socket_authorizer[policy].to_store
	not is_object(data.docker_socket_authorizer[policy].to_store)}

invalid_policies = all_policies - ok_policies

ok {
	count(invalid_policies) == 0
	count(invalid_storage) == 0
	count(ok_policies) > 0
}
`

type PolicyWatcher struct {
	watcher         *fsnotify.Watcher
	shutdownChannel chan struct{}
	isClosed        atomic.Bool
}

// Idempotent (only runs once, guaranteed by an atomic bool)
func (pw *PolicyWatcher) Close() {
	if pw.isClosed.CompareAndSwap(false, true) {
		return
	}

	pw.shutdownChannel <- struct{}{}
	close(pw.shutdownChannel)
}

func WatchPolicies() (*PolicyWatcher, error) {
	cfg := config.ConfigurationPointer.Load()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	shutdownPWChannel := make(chan struct{})

	go handlePolicyFileChange(watcher)
	go handlePolicyWatcherClose(watcher, shutdownPWChannel)

	for _, dir := range cfg.Policy.Directories {
		err = watcher.Add(dir)
		if err != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", err))
			shutdownPWChannel <- struct{}{}
			return nil, err
		}
	}
	slog.Info("Established policy watcher", slog.Any("watched", watcher.WatchList()))

	return &PolicyWatcher{
		watcher:         watcher,
		shutdownChannel: shutdownPWChannel,
	}, nil
}

func handlePolicyWatcherClose(watcher *fsnotify.Watcher, shutdownPolicyWatcher chan struct{}) {
	<-shutdownPolicyWatcher
	watcher.Close()
	slog.Info("Shutting down policy watcher")
}

func handlePolicyFileChange(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				slog.Debug("Watcher event channel closed")
				return
			}
			// exclude fsnotify.Chmod events, which can be common and don't necessarily imply we need to reevaluate the policies
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				slog.Info("File change detected", slog.String("file", event.Name), slog.String("change", event.Op.String()))
				err := LoadPolicies()
				if err != nil {
					slog.Error("Unable to reload policies", slog.Any("error", err))
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				slog.Debug("Watcher error channel closed")
				return
			}
			slog.Error("Error in policy watcher", slog.Any("error", err))
		}
	}
}

func InitializePolicies(cfg *config.Configuration) error {
	if err := LoadPolicies(); err != nil {
		return err
	}

	if cfg.Policy.WatchDirectories {
		policyWatcher, watchPoliciesErr := WatchPolicies()
		if watchPoliciesErr != nil {
			slog.Error("Unable to establish policy watcher", slog.Any("error", watchPoliciesErr))
		}
		GlobalPolicyWatcher.Store(policyWatcher)
	}

	return nil
}

func LoadPolicies() error {
	startTime := time.Now()
	defer o11y.Metrics.PolicyLoadTimer.Observe(time.Since(startTime).Seconds())

	cfg := config.ConfigurationPointer.Load()

	loadPoliciesMutex.Lock()
	defer loadPoliciesMutex.Unlock()
	o11y.Metrics.PolicyMutexWaitTimer.Observe(time.Since(startTime).Seconds())

	e, err := NewEvaluator(rego.Load(cfg.Policy.Directories, nil))
	if err != nil {
		return err
	}
	Evaluator.Store(e)

	// List all the modules except docker_socket_meta_policy
	moduleList := make([]string, len(e.authorizer.Modules())-1)
	i := 0
	for key := range e.authorizer.Modules() {
		if key == "docker_socket_meta_policy" {
			continue
		}
		moduleList[i] = key
		i++
	}
	slog.Info("Policies loaded successfully", slog.Any("policies", e.policyList), slog.Any("files_evaluated", moduleList))

	o11y.Metrics.PolicyLoads.Inc()
	return nil
}
