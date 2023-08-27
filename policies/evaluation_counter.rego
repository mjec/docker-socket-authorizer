package docker_socket_authorizer.evaluation_counter

result := "skip"
message := concat("", ["Count of policy evaluations: ", format_int(to_store["count"], 10)])
default to_store["count"] := 1

to_store["count"] = data.docker_socket_authorizer_storage.evaluation_counter.count + 1 {
    true
}
