package docker_socket_authorizer.google

import future.keywords.in

default result := "skip"
default message := "Original IP rDNS did not match"

# Match this rule by setting x-original-ip to 8.8.8.8

result = "allow" {
    "dns.google." in dns.ptr(input.request.headers["x-original-ip"][0])
    input.request.headers["x-original-ip"][0] in dns.a("dns.google.")
}

message = "Hi google" {
    result == "allow"
}

# Tests
default mock.dns.ptr(_) = []
mock.dns.ptr("8.8.8.8") =  ["dns.google."]
mock.dns.ptr("8.8.8.7") =  ["dns.google."] # So we can test PTR but not A record

mock.dns.a(_) = ["8.8.8.8"]

test_allow_if_requester_google {
    result == "allow"
        with dns.ptr as mock.dns.ptr
        with dns.a as mock.dns.a
        with input.request.headers as {"x-original-ip": ["8.8.8.8"]}
}

test_skip_if_requester_original_ip_not_google {
    result == "skip"
        with dns.ptr as mock.dns.ptr
        with dns.a as mock.dns.a
        with input.request.headers as {"x-original-ip": ["8.8.8.7"]}
}

test_skip_if_requester_rdns_not_google {
    result == "skip"
        with dns.ptr as mock.dns.ptr
        # We never call dns.a, so it doesn't matter what it returns.
        # I don't think there's a way to assert we don't call it,
        # though if you're using `opa test --capabilities ...` you
        # will get an error like "eval_internal_error: unsupported built-in"
        # if it gets called, and maybe that's enough.
}
