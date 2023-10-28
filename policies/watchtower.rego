package docker_socket_authorizer.watchtower

import future.keywords.in

default result := "skip"
default message := "Original IP rDNS did not match"

result = "allow" {
    "watchtower" in dns.ptr(input.request.headers["x-original-ip"][0])
}

# Tests
mock.dns.ptr(_) = "not-watchtower"
test_skip_if_requester_not_watchtower {
    result == "skip"
        with dns.ptr as mock.dns.ptr
        with input.request.headers as {"x-original-ip": ["127.0.0.1"]}
}