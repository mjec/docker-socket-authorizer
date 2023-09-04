package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
	"golang.org/x/exp/slog"
)

type RegoEvaluator struct {
	authorizer *rego.PreparedEvalQuery
	store      *storage.Store
	policyList []string
}

func NewEvaluator(policyLoader func(*rego.Rego)) (*RegoEvaluator, error) {
	cfg := config.ConfigurationPointer.Load()
	// TODO: @CONFIG store in files instead of inmem? A lot of extra complexity, especially on reloads
	store := inmem.NewFromObject(map[string]interface{}{
		"docker_socket_authorizer_storage": map[string]interface{}{},
	})

	transaction, err := store.NewTransaction(context.Background(), storage.WriteParams)
	if err != nil {
		return nil, err
	}

	// We have to do this nonsense to avoid aborting a stale transaction; though doing that is preferable to returning with a hanging transaction
	transactionIsCommitted := false
	defer func() {
		if !transactionIsCommitted {
			store.Abort(context.Background(), transaction)
		}
	}()

	policyMetaRego := rego.New(
		rego.Strict(cfg.Policy.StrictMode),
		rego.Module("docker_socket_meta_policy", META_POLICY),
		rego.Query(QUERY),
	)
	policyLoader(policyMetaRego)
	policyMetaQuery, err := policyMetaRego.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	policyMetaResult, err := policyMetaQuery.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	if !policyMetaResult[0].Bindings["meta_policy_ok"].(bool) {
		if prettyOutput, err := json.Marshal(policyMetaResult[0].Bindings); err != nil {
			return nil, fmt.Errorf("meta-policy validation failed and unable to serialize output to JSON (%s): %v", err, policyMetaResult[0].Bindings)
		} else {
			return nil, fmt.Errorf("meta-policy validation failed: %s", prettyOutput)
		}
	}
	policyList := make([]string, len(policyMetaResult[0].Bindings["all_policies"].([]interface{})))
	for i, policy := range policyMetaResult[0].Bindings["all_policies"].([]interface{}) {
		policyList[i] = policy.(string)
	}
	for _, policy := range policyList {
		path, ok := storage.ParsePath("/docker_socket_authorizer_storage/" + policy)
		if !ok {
			return nil, fmt.Errorf("unable to parse path to policy %s in store", policy)
		}
		store.Write(context.Background(), transaction, storage.AddOp, path, map[string]interface{}{})
	}

	newRegoObject := rego.New(
		rego.Strict(cfg.Policy.StrictMode),
		rego.Store(store),
		rego.Transaction(transaction),
		rego.Module("docker_socket_meta_policy", META_POLICY),
		rego.Query(QUERY),
	)

	var printTo io.Writer = os.Stdout
	switch cfg.Policy.PrintTo {
	case "stdout":
		printTo = os.Stdout
	case "stderr":
		printTo = os.Stderr
	case "none":
	case "":
		printTo = nil
	default:
		slog.Warn("Unsupported policy.print_to configuration value; defaulting to stdout", slog.String("print_to", cfg.Policy.PrintTo))
	}
	if printTo != nil {
		rego.EnablePrintStatements(true)(newRegoObject)
		rego.PrintHook(topdown.NewPrintHook(printTo))(newRegoObject)
	}
	policyLoader(newRegoObject)

	query, err := newRegoObject.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}

	if err := store.Commit(context.Background(), transaction); err != nil {
		return nil, err
	}
	transactionIsCommitted = true

	return &RegoEvaluator{
		authorizer: &query,
		store:      &store,
		policyList: policyList,
	}, nil
}

func (r *RegoEvaluator) EvaluateQuery(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return r.authorizer.Eval(ctx, options...)
}

func (r *RegoEvaluator) WriteToStorage(ctx context.Context, toStore map[string]interface{}) error {
	// Store has gone stale, so we're free to ignore the write (if we execute it no harm, just wasted effort)
	// WARNING: if we stop using inmem or stop resetting storage on reload, this will break.
	if r.isStale() {
		return nil
	}

	transaction, err := (*r.store).NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}
	// We have to do this nonsense to avoid aborting a stale transaction; though doing that is preferable to returning with a hanging transaction
	transactionIsCommitted := false
	defer func() {
		if !transactionIsCommitted {
			(*r.store).Abort(context.Background(), transaction)
		}
	}()

	for policy, toStore := range toStore {
		if path, ok := storage.ParsePath("/docker_socket_authorizer_storage/" + policy); !ok {
			return fmt.Errorf("unable to parse path to policy %s in store", policy)
		} else if err := (*r.store).Write(ctx, transaction, storage.AddOp, path, toStore); err != nil {
			return err
		}
	}

	if err := (*r.store).Commit(ctx, transaction); err != nil {
		return err
	}
	transactionIsCommitted = true

	return nil
}

func (r *RegoEvaluator) isStale() bool {
	return Evaluator != r
}
