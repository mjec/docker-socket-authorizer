package docker_socket_authorizer.google

import future.keywords.in

default result := "skip"
default message := "Original IP rDNS did not match"

# Match this rule by setting x-original-ip to 8.8.8.8

result = "allow" {
    "dns.google." in input.original_ip_names
}

message = "Hi google" {
    result == "allow"
}

# Tests
test_skip_if_requester_google {
    result == "allow" with input as {"original_ip_names": ["dns.google."]}
}

test_skip_if_requester_not_google {
    result == "skip" with input as {"original_ip_names": ["not-dns.google."]}
}