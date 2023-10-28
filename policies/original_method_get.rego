package docker_socket_authorizer.original_method_get

import future.keywords.in

default result := "deny"
default message := "Original method must be GET"

result = "skip" {
    upper(input.request.headers["x-original-method"][0]) == "GET"
}
message = "Original method is GET" {
    result == "skip"
}

message = "Original method not set" {
    result == "deny"
    input.request.headers["x-original-method"][0] == ""
}

message = "Original method not set" {
    result == "deny"
    not "x-original-method" in object.keys(input.request.headers)
}

# Tests
test_allow_if_method_is_get {
    # Not case sensitive
    result == "skip" with input.request.headers as {"x-original-method": ["get"]}
    result == "skip" with input.request.headers as {"x-original-method": ["GET"]}
    result == "skip" with input.request.headers as {"x-original-method": ["gEt"]}
}

test_deny_if_method_is_not_get {
    result == "deny" with input.request.headers as {"x-original-method": ["post"]}
    message == "Original method must be GET" with input.request.headers as {"x-original-method": ["get "]}
    result == "deny" with input.request.headers as {"x-original-method": ["get "]}
    message == "Original method must be GET" with input.request.headers as {"x-original-method": [" x "]}
}

test_prohibit_if_method_is_not_set {
    result == "deny" with input.request.headers as {"x-original-method": [""]}
    message == "Original method not set" with input.request.headers as {"x-original-method": [""]}
    result == "deny" with input.request.headers as {}
    message == "Original method not set" with input.request.headers as {}
}
