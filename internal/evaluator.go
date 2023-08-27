package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
)

type RegoEvaluator struct {
	authorizer *rego.PreparedEvalQuery
	store      *storage.Store
	policyList []string
}

func NewEvaluator(policyLoader func(*rego.Rego)) (*RegoEvaluator, error) {
	rego_object := rego.New(
		// TODO: @CONFIG strict mode?
		rego.Strict(true),
		rego.Module("docker_socket_meta_policy", META_POLICY),
		rego.Query("output := data.docker_socket_meta_policy; ok := output.ok"),
	)
	policyLoader(rego_object)
	meta_policy_validity_query, err := rego_object.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	meta_policy_validity_result, err := meta_policy_validity_query.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	if !meta_policy_validity_result[0].Bindings["ok"].(bool) {
		if pretty_output, err := json.Marshal(meta_policy_validity_result[0].Bindings["output"]); err != nil {
			return nil, fmt.Errorf("meta policy validation failed and unable to serialize output to JSON (%s): %v", err, meta_policy_validity_result[0].Bindings["output"])
		} else {
			return nil, fmt.Errorf("meta policy validation failed: %s", pretty_output)
		}
	}

	// TODO: @CONFIG store in files instead of inmem? A lot of extra complexity, especially on reloads
	store := inmem.NewFromObject(map[string]interface{}{
		"docker_socket_authorizer_storage": map[string]interface{}{},
	})

	transaction, err := store.NewTransaction(context.Background(), storage.WriteParams)
	if err != nil {
		return nil, err
	}

	// We have to do this nonsense to avoid aborting a stale transaction
	transaction_is_committed := false
	defer func() {
		if !transaction_is_committed {
			store.Abort(context.Background(), transaction)
		}
	}()

	policy_list_rego := rego.New(
		// TODO: @CONFIG strict mode?
		rego.Strict(true),
		rego.Query("policies = [policy | data.docker_socket_authorizer[policy]]"),
	)
	policyLoader(policy_list_rego)
	policy_list_query, err := policy_list_rego.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	policy_list_result, err := policy_list_query.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	policy_list := make([]string, len(policy_list_result[0].Bindings["policies"].([]interface{})))
	for i, policy := range policy_list_result[0].Bindings["policies"].([]interface{}) {
		policy_list[i] = policy.(string)
	}
	for _, policy := range policy_list {
		path, ok := storage.ParsePath("/docker_socket_authorizer_storage/" + policy)
		if !ok {
			return nil, fmt.Errorf("unable to parse path to policy %s in store", policy)
		}
		store.Write(context.Background(), transaction, storage.AddOp, path, map[string]interface{}{})
	}

	new_rego_object := rego.New(
		// TODO: @CONFIG print mode
		rego.EnablePrintStatements(true),
		rego.PrintHook(topdown.NewPrintHook(os.Stdout)),
		// TODO: @CONFIG strict mode?
		rego.Strict(true),
		rego.Store(store),
		rego.Transaction(transaction),
		rego.Module("docker_socket_meta_policy", META_POLICY),
		rego.Query(QUERY),
	)
	policyLoader(new_rego_object)

	query, err := new_rego_object.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}

	if err := store.Commit(context.Background(), transaction); err != nil {
		return nil, err
	}
	transaction_is_committed = true

	return &RegoEvaluator{
		authorizer: &query,
		store:      &store,
		policyList: policy_list,
	}, nil
}

func (r *RegoEvaluator) EvaluateQuery(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return r.authorizer.Eval(ctx, options...)
}

func (r *RegoEvaluator) WriteToStorage(ctx context.Context, to_store map[string]interface{}) error {
	// Store has gone stale, so we're free to ignore the write (if we execute it no harm, just wasted effort)
	// WARNING: if we stop using inmem or stop resetting storage on reload (@CONFIG), this will break.
	if r.isStale() {
		return nil
	}

	transaction, err := (*r.store).NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}

	for policy, to_store := range to_store {
		if path, ok := storage.ParsePath("/docker_socket_authorizer_storage/" + policy); !ok {
			return fmt.Errorf("unable to parse path to policy %s in store", policy)
		} else if err := (*r.store).Write(ctx, transaction, storage.AddOp, path, to_store); err != nil {
			return err
		}
	}

	if err := (*r.store).Commit(ctx, transaction); err != nil {
		return err
	}

	return nil
}

func (r *RegoEvaluator) isStale() bool {
	return Evaluator != r
}
