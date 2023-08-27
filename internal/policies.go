package internal

import (
	"log"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/open-policy-agent/opa/rego"
)

var (
	Evaluator *RegoEvaluator = nil
)

// This query MUST produce the following outputs for handlers/authorizer.go to work at all:
// - ok: boolean, true if the request is approved
// - to_store: map[string]interface{}, a map from policy to data to store for that policy
//
// The following SHOULD to be available for logging in handlers/authorizer.go:
// - denies: map[string][string], the deny messages from each policy
// - allows: map[string][string], the allow messages from each policy
// - skips: map[string][string], the skip messages from each policy
// - invalid_policies: set, the names of all policies that fail to produce both a message and valid result (deny/skip/allow)
// - invalid_storage: set, the names of all policies that have invalid storage
//
// We also assert the following, which is guaranteed by the meta policy:
//
//	count(all_policies) == count(denies) + count(allows) + count(skips) + count(invalid_policies)
//
// That assertion is fundamental: all valid policies must produce exactly one of those three results.
// Although we check that in the meta policy, we also check it here to ensure that the query is safe
// even if the meta policy contains a bug.
const QUERY = `
denies = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "deny"}
allows = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "allow"}
skips = {policy: data.docker_socket_authorizer[policy].message | data.docker_socket_authorizer[policy].result == "skip"}

invalid_policies = data.docker_socket_meta_policy.invalid_policies
invalid_storage = data.docker_socket_meta_policy.invalid_storage

to_store = {policy: data.docker_socket_authorizer[policy].to_store | true}
ok = count({x | [count(invalid_policies) == 0, count(denies) == 0, count(allows) > 0][x] == true}) == 3

# Baseline legitimacy check: all policies should have a result of allow, deny or skip; or be invalid
count({policy | data.docker_socket_authorizer[policy]}) == count(denies) + count(allows) + count(skips) + count(invalid_policies)
`

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

func WatchPolicies() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Printf("Watcher event channel closed\n")
					return
				}
				// exclude fsnotify.Chmod events, which can be common and don't necessarily imply we need to reevaluate the policies
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
					log.Printf("File change detected: %s\n", event.Name)
					err := LoadPolicies()
					if err != nil {
						log.Printf("Unable to reload policies: %s", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					log.Printf("Watcher error channel closed\n")
					return
				}
				log.Printf("Error in file watcher: %s\n", err)
			}
		}
	}()

	err = watcher.Add("./policies/") // TODO: @CONFIG policies directory
	if err != nil {
		log.Fatalf("Unable to add watcher to policies directory: %s", err)
	}
	log.Printf("Setting up policy watcher: %v\n", watcher.WatchList())

	<-make(chan struct{})
}

func LoadPolicies() error {
	start_time := time.Now()
	defer o11y.Metrics.PolicyLoadTimer.Observe(time.Since(start_time).Seconds())

	// TODO: @CONFIG policies directory
	e, err := NewEvaluator(rego.Load([]string{"./policies/"}, nil))
	if err != nil {
		return err
	}
	Evaluator = e
	log.Printf("Policies loaded successfully: %s\n", strings.Join(e.policyList, ", "))

	o11y.Metrics.PolicyLoads.Inc()
	return nil
}
