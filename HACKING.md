# Changing docker-socket-authorizer

## Adding new inputs

The set of available inputs is determined by the `MakeInput()` function in `internal/input.go`. To add a new input:

- add an appropriate public field to the `Input` struct, including an appropriate `json` key in the field tag; and
- modify `MakeInput()` to set that field from the `http.Request`

## Updating the query

If you are making changes to the query, please **update this document** to reflect those changes.

The query is what's relied on by the authorizer in `internal/handlers/authorizer.go` to determine if the request should be permitted.

Generally it should not be necessary to adjust the query. Changes may have far-reaching effects in the code, and it is up to you to ensure you've found all the appropriate places where behavior may change. You may also need to update the meta-policy, which is tightly coupled to the query.

The query should assert any condition fundamental to producing correct output so it does not behave unpredictably even if there is a bug in the meta-policy. For example, at the time of writing the query includes the following assertion:

```rego
count({policy | data.docker_socket_authorizer[policy]}) == count(denies) + count(allows) + count(skips) + count(invalid_policies)
```

### Output variables

The query must produce the following outputs:

Variable | Type | Description
-------- | ---- | -----------
`ok` | boolean | True if and only if the request is approved
`meta_policy_ok` | boolean | True if and only if the meta-policy passes
`all_policies` | []string | A list of the names of policies that are loaded under the `docker_socket_authorizer` namespace
`to_store` | map\[string\]interface{} | A map from policy to data to store for that policy

These outputs are used in `internal/evaluator.go` and `internal./handlers/authorizer.go`.

We also document the following outputs as existing for logging purposes, but changes to those outputs will only affect logging and not the correct operation of the system:

Variable | Type | Description
-------- | ---- | -----------
`denies` | map\[string\]string | A map from policy to message for each policy with a result of "deny"
`allows` | map\[string\]string | A map from policy to message for each policy with a result of "allow"
`skips` | map\[string\]string | A map from policy to message for each policy with a result of "skip"
`ok_conditions` | map\[string\]bool | A map from success condition to whether or not that condition passed

## Updating the meta-policy

If you are making changes to the meta-policy, please **update this document** to reflect those changes.

The meta-policy exists to ensure all policies work in accordance with the requirements of the query. To change the meta-policy, update it in `internal/policies.go`. It is a standard rego policy, with the package name `docker_socket_meta_policy`.

The meta-policy and query are tightly coupled. The intent of the meta-policy is that it should fail if any evaluated policy fails to produce a result appropriate for the query.

### Output variables

The meta-policy must produce the following outputs:

Variable | Type | Description
-------- | ---- | -----------
`ok` | boolean | True if and only if the meta-policy passes
`all_policies` | []string | A list of the names of policies that are loaded under the `docker_socket_authorizer` namespace
`invalid_policies` | []string | A list of policy names that do not produce a valid `result` and `message`
`invalid_storage` | []string | A list of policy names that do not produce a valid `to_store` object
