# Changing docker-socket-authorizer

## Adding new inputs

The set of available inputs is determined by the `MakeInput()` function in `internal/input.go`. To add a new input:

- add an appropriate public field to the `Input` struct, including an appropriate `json` key in the field tag; and
- modify `MakeInput()` to set that field from the `http.Request`

## Updating the meta-policy

TODO: document meta policy

## Updating the query

TODO: document query
