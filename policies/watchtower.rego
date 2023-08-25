package docker_socket_authorizer.watchtower

import future.keywords.in

default result := "skip"
default message := "Original IP rDNS did not match"

result = "allow" {
    "watchtower" in input.original_ip_names
}

# Tests
test_skip_if_requester_not_watchtower {
    result == "skip" with input as {"original_ip_names": ["not watchtower"]}
}