package policy

import (
	"errors"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/gqlguard"
)

// maxDataOffset caps offset and skip, because a deep offset still makes the database read
// every skipped row.
const maxDataOffset = 10_000

// ContemberGraphQL is a read-only Content API query for one project stage, checked against the
// role's schema and the scope's entity and field rules.
type ContemberGraphQL struct {
	scope authz.ContemberScope
	query string
	rows  int
}

func (q ContemberGraphQL) String() string              { return q.query }
func (q ContemberGraphQL) Scope() authz.ContemberScope { return q.scope }

// Rows is the maximum number of rows the query can return, from its limits.
func (q ContemberGraphQL) Rows() int { return q.rows }

// DataRules are the gqlguard rules of a scope under the given limits.
func DataRules(scope authz.ContemberScope, limits config.Limits) gqlguard.Rules {
	return gqlguard.Rules{
		Entities:  scope.Entities(),
		Denied:    scope.Denied,
		MaxRows:   limits.DataMaxRows,
		MaxDepth:  limits.DataMaxDepth,
		MaxFields: limits.DataMaxFields,
		MaxOffset: maxDataOffset,
	}
}

// ScopeContemberGraphQL checks the agent's query and variables and returns the normalized
// query with fragments and variables inlined.
func ScopeContemberGraphQL(scope authz.ContemberScope, schema *gqlguard.Schema, query string, variables []byte, limits config.Limits) (ContemberGraphQL, error) {
	if size := len(query) + len(variables); size > limits.DataMaxQueryBytes {
		return ContemberGraphQL{}, apierr.New(api.CodeLimitExceeded, "query and variables have %d bytes, the limit is %d", size, limits.DataMaxQueryBytes)
	}
	res, err := gqlguard.Check(schema, query, variables, DataRules(scope, limits))
	if err != nil {
		var rejected *gqlguard.Error
		if errors.As(err, &rejected) {
			return ContemberGraphQL{}, apierr.InvalidQuery("%s", rejected.Message)
		}
		return ContemberGraphQL{}, err
	}
	// Inlined variables and fragments can make the normalized query much larger than the
	// input. It runs upstream, goes to the audit log and back to the agent, so it gets the
	// same limit.
	if len(res.Query) > limits.DataMaxQueryBytes {
		return ContemberGraphQL{}, apierr.New(api.CodeLimitExceeded, "the query has %d bytes after variables and fragments are inlined, the limit is %d", len(res.Query), limits.DataMaxQueryBytes)
	}
	return ContemberGraphQL{scope: scope, query: res.Query, rows: res.Rows}, nil
}
