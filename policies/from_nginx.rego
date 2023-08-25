package docker_socket_authorizer.from_nginx

import future.keywords.in

default result := "deny"
default message := "Connection did not come from nginx"

result = "skip" {
    data.configuration.nginx_hostname in input.remote_addr_names
}

message = "Connection came from nginx" {
    result == "skip"
}

# Tests
test_skip_if_nginx {
    result == "skip" with input as {"remote_addr_names": [data.configuration.nginx_hostname]}
}

test_deny_if_not_nginx {
    result == "deny" with input as {"remote_addr_names": [concat(":", ["not", data.configuration.nginx_hostname])] }
}
