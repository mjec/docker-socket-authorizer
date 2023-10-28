package docker_socket_authorizer.from_nginx

import future.keywords.in

default result := "deny"
default message := "Connection did not come from nginx"

result = "skip" {
    data.configuration.nginx_hostname in dns.ptr(input.request.remote_addr)
}

message = "Connection came from nginx" {
    result == "skip"
}

# Tests
default mock.dns.ptr(_) := []
mock.dns.ptr("127.0.0.1") = [data.configuration.nginx_hostname]
test_skip_if_nginx {
    result == "skip"
        with dns.ptr as mock.dns.ptr
        with input.request.remote_addr as "127.0.0.1"
}

test_deny_if_not_nginx {
    result == "deny"
        with dns.ptr as mock.dns.ptr
        with input.request.remote_addr as "8.8.8.8"
}
