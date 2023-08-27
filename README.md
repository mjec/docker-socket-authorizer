# docker-socket-authorizer

A service to be called by nginx `auth_request` for controlling access to a docker socket.

This uses the [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) language [rego](https://www.openpolicyagent.org/docs/v0.55.0/policy-language/) to define policies for when to allow and when to prohibit requests.

## TODO

This thing is not complete. It is approximately functional.

### Release blockers

- [ ] Tests for go
- [ ] Structured logs
- [ ] Tracing
- [ ] Better metrics configuration and documentation
- [ ] Configuration (marked as `@CONFIG`)
- [ ] Additional functions, e.g. `dockerHost("watchtower")` becomes `watchtower.docker_net_name.` where `docker_net_name` is set by environment variable or config
- [ ] add (some) config to input, producing `input.config`
- [ ] CI, code of conduct
- [ ] Listen on unix socket (but prometheus remains on tcp?)
- [ ] rDNS timeout

### Decisions to  be made

- [ ] Extensible input, maybe? So like, easier to define new inputs, maybe even with some kind of plugin
- [ ] Should introspection be only through an endpoint? Could curl instead of `introspect`
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
    proxy_pass http://authorizer:8080/authorize;
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

Endpoint | Description
-------- | -----------
`/reflect` | Returns a JSON object representing the `input` object passed to OPA by `/authorize`
`/reload` | When called with `POST` method, reloads policies
`/metrics` | Prometheus metrics for the service
`/authorize` | Applies policies and returns either `OK` and an HTTP 200 status code, or `Forbidden` and a 403 status code

Note that there is no authorization required to hit any of these endpoints.

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

TODO: add structured logs

TODO: document values in logs (especially `input` and `result`)

### Metrics

TODO: document prometheus metrics

### Traces

TODO: add tracing

## Configuration

TODO: @CONFIG add configuration docs

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
`original_ip_names` | []string | A list of names returned from doing an rDNS lookup of `original_ip`
`original_uri` | string | The original request URI (including query string)
`original_method` | string | The original request method
`original_ip` | string | The original request IP address
`uri` | string | The request current URI (including query string)
`remote_addr` | string | The address and port of the other side of the present connection (normally this will match nginx)
`remote_addr_names` | []string | A list of names returned from doing an rDNS lookup of the IP address in `remote_addr`

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

It is also appropriate to use `opa eval` to run manual tests of policies. Doing so requires an input, query, and policy. To aid in this, you can call the application with the `introspect` command, as follows:

Command | Output
------- | ------
`introspect query` | The OPA query used to evaluate requests
`introspect meta-policy` | The meta-policy that governs whether policies are valid
`introspect input` | An empty JSON object matching the structure of `input`

You can also obtain a valid input by hitting the `/reflect` endpoint.

This means you can manually test your policies by running something like the following (broken up onto multiple lines for readability):

```bash
~/opa eval \
    "$(docker-socket-authorizer introspect query)" \
    --strict \
    --data <(docker-socket-authorizer introspect meta-policy) \
    --data policies/watchtower.rego \
    --input <(docker-socket-authorizer introspect input | jq '.original_ip_names = ["localhost"]') \
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
