package internal

import "github.com/open-policy-agent/opa/rego"

var (
	RegoObject *rego.Rego              = nil
	Authorizer *rego.PreparedEvalQuery = nil
)
