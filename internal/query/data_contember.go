package query

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/contember"
	"github.com/contember/sonda/internal/gqlguard"
	"github.com/contember/sonda/internal/policy"
)

// schemaLoadTimeout bounds one introspection, also at startup.
const schemaLoadTimeout = 15 * time.Second

type contemberData struct {
	scope   authz.ContemberScope
	client  *contember.Client
	schemas *schemaCache
	limits  config.Limits
}

func newContemberData(scope authz.ContemberScope, client *contember.Client, schemas *schemaCache, limits config.Limits) dataBackend {
	return &contemberData{scope: scope, client: client, schemas: schemas, limits: limits}
}

func (b *contemberData) dialect() api.Dialect { return api.DialectContemberGraphQL }

func (b *contemberData) schema(ctx context.Context) (*gqlguard.Schema, gqlguard.Rules, error) {
	key := b.scope.Source().Name + "/" + b.scope.Project() + "/" + b.scope.Stage()
	schema, err := b.schemas.get(key, func() (*gqlguard.Schema, error) {
		// Concurrent requests share this load, so it must not end when the first caller's
		// request does.
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), schemaLoadTimeout)
		defer cancel()
		return LoadContemberSchema(loadCtx, b.client, b.scope)
	})
	return schema, policy.DataRules(b.scope, b.limits), err
}

func (b *contemberData) query(ctx context.Context, text string, variables json.RawMessage) (dataQuery, error) {
	schema, _, err := b.schema(ctx)
	if err != nil {
		return dataQuery{}, err
	}
	q, err := policy.ScopeContemberGraphQL(b.scope, schema, text, variables, b.limits)
	if err != nil {
		return dataQuery{}, err
	}
	recordQuery(ctx, b.scope.Target, q.String())
	data, err := b.client.Query(ctx, q)
	if err != nil {
		return dataQuery{}, err
	}
	return dataQuery{
		query: q.String(),
		rows:  q.Rows(),
		data:  data,
		// The query is already in data.query; it is not repeated here.
		source: api.SourceRef{Kind: string(config.SourceContember)},
	}, nil
}

// LoadContemberSchema introspects the project stage and refuses an API key whose role can
// write: Sonda must never hold a credential that could change data.
func LoadContemberSchema(ctx context.Context, client *contember.Client, scope authz.ContemberScope) (*gqlguard.Schema, error) {
	data, err := client.Introspect(ctx, scope)
	if err != nil {
		return nil, err
	}
	schema, err := gqlguard.LoadIntrospection(data)
	if err != nil {
		return nil, apierr.Upstream("source %s: %v", scope.Source().Name, err)
	}
	if write := schema.WriteFields(); len(write) > 0 {
		shown := write[:min(len(write), 3)]
		return nil, &writeAccessError{err: apierr.Upstream("source %s is disabled: its API key can write (%s); give it a read-only role", scope.Source().Name, strings.Join(shown, ", "))}
	}
	return schema, nil
}

// writeAccessError marks a key that can write, so the server can refuse to start.
type writeAccessError struct {
	err *apierr.Error
}

func (e *writeAccessError) Error() string { return e.err.Error() }
func (e *writeAccessError) Unwrap() error { return e.err }
