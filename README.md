# docker-socket-authorizer

A service to be called by nginx `auth_request` for controlling access to a docker socket.

This uses the [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) language [rego](https://www.openpolicyagent.org/docs/v0.55.0/policy-language/) to define policies for when to allow and when to prohibit requests.

## TODO

This thing is not complete. It is approximately functional.

### Release blockers

- [ ] Tests for go
- [ ] Tracing
- [ ] Better metrics configuration and documentation
- [ ] Additional functions, e.g. `dockerHost("watchtower")` becomes `watchtower.docker_net_name.` where `docker_net_name` is set by environment variable or config
- [ ] Refactor `input`: `input.request`, `input.config` etc
- [ ] Make `rdns` a built-in function, rather than applying it to all inputs in the application (this can be done in policy instead)
- [ ] CI, code of conduct
- [ ] rDNS timeout
- [ ] Make query just `ok` and permit configuring query and meta-policy

### Decisions to  be made

- [ ] Extensible input, maybe? So like, easier to define new inputs, maybe even with some kind of plugin
- [ ] What do I call this thing? Is it really docker-specific enough to have this name? (no) Maybe opa-nginx or something?
- [ ] Should this be a pass-through proxy instead of an authorization agent? I think no, though that would give us the body of every request
- [ ] Should rDNS be configurable? I mean, it should definitely be disable-able, but should you be able to set servers or other resolver options? Timeouts?

## Quick start

### Example nginx configuration

```nginx
location / {
    auth_request /authorization;
    proxy_pass http://unix:/var/run/docker.sock:/;
}

location /authorization {
    internal;
    proxy_pass http://unix:/var/run/authorizer.sock:/authorize;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-IP $remote_addr;
}
```

### Example policy

```rego
package docker_socket_authorizer.watchtower

import future.keywords.in

default result := "skip"
default message := "Original IP rDNS did not match"

result = "allow" {
    "watchtower" in input.original_ip_names
}

message = "Watchtower is allowed to do anything" {
    result == "allow"
}

# Tests
test_allow_if_requester_is_watchtower {
    result == "skip" with input as {"original_ip_names": ["watchtower"]}
}
test_skip_if_requester_not_watchtower {
    result == "skip" with input as {"original_ip_names": ["not watchtower"]}
}
```

## Calling the authorizer

### Available endpoints

Endpoint | Configuration | Description
-------- | ------ | -----------
`/authorize` | N/A | Applies policies and returns either `OK` and an HTTP 200 status code, or `Forbidden` and a 403 status code
`/reflection/configuration` | `reflection.enabled` | Returns a JSON object representing the currently active configuration
`/reflection/default-configuration` | `reflection.enabled` | Returns a JSON object representing the default configuration
`/reflection/input` | `reflection.enabled` | Returns a JSON object representing the `input` object passed to OPA by `/authorize` for this request
`/reflection/query` | `reflection.enabled` | Returns the [query](HACKING.md#updating-the-query) evaluated against the policies
`/reflection/meta-policy` | `reflection.enabled` | Returns the [meta-policy](HACKING.md#updating-the-meta-policy)
`/reload/configuration` | `reload.configuration` | When called with `POST` method, reloads configuration (though some configuration options require a restart); also restarts policy watcher (if appropriate) and reopens the log file
`/reload/policies` | `reload.policies` | When called with `POST` method, reloads policies
`/reload/reopen-log-file` | `reload.reopen_log_file` | When called with `POST` method, reopens log file (for example, for use with logrotate)
`/metrics`* | `authorizer.includes_metrics`** | Prometheus metrics for the service

Note that there is no authorization required to hit any of these endpoints, however each endpoint will be accessible if and only if the associated configuration option is set to `true`.

\* This is the default path, but can be changed by the `metrics.path` configuration option.

\*\* This option determines whether the metrics endpoint is available on the same listener as the other endpoints; however it will always be available at the value of the `metrics.path` configuration option (default `/metrics`) on the listener address set in the `metrics.listener` configuration option.

### Required HTTP headers

Header | Value
------ | -----
`x-original-uri` | The original request URI to authorize
`x-original-method` | The original request method
`x-original-ip` | The originating IP address of the request

### Authentication

This system does not have any authentication per se. Requests to `/authorize` are anticipated to come from a trusted source.

When converting an IP address into a list of names (for `original_ip_names` or `remote_addr_names`), the names are only those which match for both reverse *and forward* lookups.

## Observability

TODO: observability docs

### Logs

Logs are written as JSON lines.

#### Authorization logs

Of particular interest are info log lines with `msg` of `Request processed`. These represent calls to `/authorize` where we did not encounter an error.

These lines may contain the following attributes:

Variable | Type | Configuration | Description | Available fields
-------- | ---- | ------------- | ----------- | ----------------
`input` | map\[string\]interface{} | `log.input` | A subset of inputs used to evaluate this request | See [Available Inputs](#available-inputs)
`result` | map\[string\]interface{} | `log.result` | A subset of results of evaluating this request | See [Available Results](#available-results)

The relevant configuration option determines what subset of fields is logged. Each of those options is a list of the names of the top-level fields to include in the log. By default only the `result.ok` field is logged, and all others are ignored.

If the list of fields to be logged is empty, then that attribute will not be logged at all.

If the list of fields contains a single element which is the string "*", then all fields will be logged.

##### Available results

The available top-level properties of `result` include:

Variable | Type | Description
-------- | ---- | -----------
`ok` | bool | True if and only if the result was a pass
`ok_conditions` | map\[string\]bool | A map from success condition to whether or not that condition passed
`all_policies` | []string | A list of the names of policies that were evaluated under the `docker_socket_authorizer` namespace
`allows` | map\[string\]string | A map from policy to message for each policy with a result of "allow"
`denies` | map\[string\]string | A map from policy to message for each policy with a result of "deny"
`skips` | map\[string\]string | A map from policy to message for each policy with a result of "skip"

Other properties may exist, and you should not rely on this list being exhaustive. The actual list is determined by the query. For more, see [HACKING.md](HACKING.md#updating-the-query).

### Metrics

Prometheus metrics are available on the `/metrics` path.

### Traces

TODO: add tracing

## Configuration

All available configuration options are listed and explained in [`config.example.yaml`](config.example.yaml).

Note that some configuration options are only applied on restart, and not on reload, as documented in the example.

## Writing policies

### Naming

Policies can have any package name and all will be evaluated, but there must be at least one in the `docker_socket_authorizer` namespace. Within that namespace, no further nesting is supported (i.e. while `docker_socket_authorizer.foo` is ok, `docker_socket_authorizer.foo.bar` is an error).

### How policies are evaluated

For a request to be approved, the following conditions must all be true:

- every policy under `docker_socket_authorizer` must set `result` and `message` variables
- there must not be such a policy with the result of `deny`
- at least one such policy must have a result of `allow`

As a consequence, you can think of policies as being either:

- global `docker_socket_authorizer` policies that are required to pass for *all* requests (by producing a result of `skip` when the pass and `deny` when they fail)
- `docker_socket_authorizer` policies that authorize requests that match their criteria (by producing a result of `skip` when criteria do not match, `allow` when they pass, and `deny` when they fail)
- non-`docker_socket_authorizer` policies, which do not alone influence the authorization of a request

Note that **only a single `allow` is required** for a request to pass. For example, there is no concept of "if any of policies X, Y or Z is not `skip`, then all must be `allow`". Any such logic must be implemented in policy.

It is possible to use non-`docker_socket_authorizer` policies for any purpose. For example, you may have a `configuration.rego` like:

```rego
package configuration

nginx_hostname := "localhost"
```

And then you could access that data through the `data.configuration.nginx_hostname` variable in other policies.

All policies are always evaluated in [strict mode](https://www.openpolicyagent.org/docs/v0.55.0/policy-language/#strict-mode).

### Output variables

Every `docker_socket_authorizer` policy must produce `result` and `message` variables, and may set a `to_store` variable as well.

Variable | Type | Description
-------- | ---- | -----------
`result` | string | Must be one of `allow`, `skip` or `deny` (case sensitive)
`message` | string | Must be a non-empty string explaining the reason for the result
`to_store` | object\|undefined | If set, will be made available to subsequent evaluations as `data.docker_socket_authorizer_storage.$policy` (where `$policy` is the policy name under `docker_socket_authorizer`)

These requirements are enforced by a meta-policy that cannot be disabled.

### Available inputs

The `input` variable in each policy contains the following properties.

Input name | Type | Description
---------- | ---- | -----------
`request.uri` | string | The request current URI (including query string)
`request.remote_addr` | string | The address and port of the other side of the present connection
`request.headers` | map\[string\]\[\]string | All keys lowercase
`request.body` | string | Request body

Changing available inputs requires changing the code; for more see [HACKING.md](HACKING.md).

### Storing state

The `to_store` variable for a given policy will be persisted across policy evaluations, where it will be made available as `data.docker_socket_authorizer_storage.$policy` (where `$policy` is the policy name under `docker_socket_authorizer`).

#### Example

Consider this policy:

```rego
package docker_socket_authorizer.evaluation_counter

result := "skip"
message := concat("", ["Count of policy evaluations: ", format_int(to_store["count"], 10)])
default to_store["count"] := 1

to_store["count"] = data.docker_socket_authorizer_storage.evaluation_counter.count + 1 {
    true
}
```

The value of `to_store["count"]` defaults to 1. That means that if nothing else sets that, the next time this policy is evaluated `data.docker_socket_authorizer_storage.evaluation_counter.count` will be equal to `1`.

We do set the value of `to_store["count"]` to `data.docker_socket_authorizer_storage.evaluation_counter.count + 1`. This is only satisfiable if `data.docker_socket_authorizer_storage.evaluation_counter.count` has a value, which means we stored it last time.

As a result, `data.docker_socket_authorizer_storage.evaluation_counter.count` will increase by one on every evaluation. The current evaluation counter (which starts at 1 on the first evaluation) is the value in `to_store["count"]`, so we include that in the message.

#### Caveats

Stored values are reset whenever the application is restarted or new policies are loaded.

To be valid, `to_store` must always be a map with string keys. As such, using `to_store["key_name"]` is idiomatic. Attempting to store scalars directly into `to_store` will fail the meta-policy:

```rego
to_store := 1 { # WRONG
    true
}
```

### Tests

OPA has a [built-in testing framework](https://www.openpolicyagent.org/docs/v0.55.0/policy-testing/) that can be used to ensure policies are correct. Those tests are not run by this application, but are useful when developing policies.

Be aware that if you wish to use a function provided by docker-socket-authorizer (e.g. `dns.ptr` or `dns.a`) you cannot test those. You can however run `opa capabilities --current` and then patch with capabilities.json.patch and then run `opa test --capabilities capabilities.json` and you'll be fine as long as you have mocked out those docker-socket-authorizer built-ins, and you have done so as _actual function mocks_ not just setting them to fixed values.

It is also appropriate to use `opa eval` to run manual tests of policies. Doing so requires an input, query, and policy. This means you can manually test your policies by running something like the following (broken up onto multiple lines for readability):

```bash
opa eval \
    "$(curl -s --unix-socket serve.sock http://x/reflection/query)" \
    --strict \
    --data <(curl -s --unix-socket serve.sock http://x/reflection/meta-policy) \
    --data policies/watchtower.rego \
    --input <(curl -s --unix-socket serve.sock http://x/reflection/input | jq '.request.headers["x-original-ip"] = ["127.0.0.1"]') \
    | jq '.result[].bindings'
```

Here you would want to replace `your-policy.rego` with a path to your policy; and modify the arguments to `jq` as appropriate to set your test input.

It's valuable to understand what this is doing, in order to modify it appropriately. Specifically:

- `--input` takes a JSON file that contains the input to pass in; you may prefer to set this to a real file and make progressive changes in the file
- `jq '.result[].bindings` returns just the output bindings from the evaluation, which include the data that would be available in logs; however removing this entirely will provide much more information about what variables are set and why
- You may wish to save the query and meta-policy to a file, and remove some parts of it, in order to accelerate testing and debugging

If evaluating your policy results in a null output, this likely means a bug in the meta-policy. Consider removing the following final line from the query in order to get more information for:

```rego
count({policy | data.docker_socket_authorizer[policy]}) == count(denies) + count(allows) + count(skips) + count(invalid_policies)
```

## Extending docker-socket-authorizer

For more on updating the code, see [HACKING.md](HACKING.md).
