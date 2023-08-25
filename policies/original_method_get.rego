package docker_socket_authorizer.original_method_get

import future.keywords.in

default result := "deny"
default message := "Original method must be GET"

result = "skip" {
    upper(input.original_method) == "GET"
}
message = "Original method is GET" {
    result == "skip"
}

message = "Original method not set" {
    result == "deny"
    input.original_method == ""
}

message = "Original method not set" {
    result == "deny"
    not "original_method" in object.keys(input)
}

store = {
    "count": 1,
} {
    result == "skip"
}

# Tests
test_allow_if_method_is_get {
    # Not case sensitive
    result == "skip" with input as {"original_method": "get"}
    result == "skip" with input as {"original_method": "GET"}
    result == "skip" with input as {"original_method": "gEt"}
}

test_deny_if_method_is_not_get {
    result == "deny" with input as {"original_method": "post"}
    message == "Original method must be GET" with input as {"original_method": "get "}
    result == "deny" with input as {"original_method": "get "}
    message == "Original method must be GET" with input as {"original_method": " x "}
}

test_prohibit_if_method_is_not_set {
    result == "deny" with input as {"original_method": ""}
    message == "Original method not set" with input as {"original_method": ""}
    result == "deny" with input as {}
    message == "Original method not set" with input as {}
}
