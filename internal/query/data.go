package query

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/gqlguard"
	"github.com/contember/sonda/internal/shape"
)

// schemaTTL is how long an introspected schema is reused. Every refresh repeats the check
// that the API key cannot write, so a later ACL change that adds write access disables the
// binding within this time.
const schemaTTL = 10 * time.Minute

var dataUntrusted = []string{"data.data"}

// dataBackend runs data use cases for one scope.
type dataBackend interface {
	dialect() api.Dialect
	schema(ctx context.Context) (*gqlguard.Schema, gqlguard.Rules, error)
	query(ctx context.Context, text string, variables json.RawMessage) (dataQuery, error)
}

type dataQuery struct {
	query  string
	rows   int
	data   json.RawMessage
	source api.SourceRef
}

func (s *Service) dataBackend(scope authz.DataScope, identity *authz.Identity) (dataBackend, error) {
	if cs, ok := scope.Contember(); ok {
		return newContemberData(cs, s.connectors.Contember[cs.Source().Name], s.schemas, identity.Limits), nil
	}
	return nil, unsupported("data", scope.Source())
}

func (s *Service) dataScope(identity *authz.Identity, service, env string) (authz.DataScope, dataBackend, error) {
	scope, err := s.authz.DataScope(identity, service, env)
	if err != nil {
		return authz.DataScope{}, nil, err
	}
	backend, err := s.dataBackend(scope, identity)
	if err != nil {
		return authz.DataScope{}, nil, err
	}
	return scope, backend, nil
}

// DataSchema describes the entities and fields the identity may read in the environment.
func (s *Service) DataSchema(ctx context.Context, identity *authz.Identity, service, env string) (api.Response[api.DataSchema], error) {
	scope, backend, err := s.dataScope(identity, service, env)
	if err != nil {
		return api.Response[api.DataSchema]{}, err
	}
	schema, rules, err := backend.schema(ctx)
	if err != nil {
		return api.Response[api.DataSchema]{}, err
	}
	entities, enums := schema.Visible(rules)
	result := api.DataSchema{Entities: make([]api.DataEntity, 0, len(entities))}
	if len(enums) > 0 {
		result.Enums = enums
	}
	for _, e := range entities {
		entity := api.DataEntity{Name: e.Name, Unique: e.Unique, Fields: make([]api.DataField, len(e.Fields))}
		for i, f := range e.Fields {
			entity.Fields[i] = api.DataField(f)
		}
		result.Entities = append(result.Entities, entity)
	}
	return api.Response[api.DataSchema]{Data: result, Meta: api.Meta{Service: scope.Service(), Environment: scope.Environment()}}, nil
}

// QueryData runs a read-only GraphQL query in the dialect of the service's data source.
func (s *Service) QueryData(ctx context.Context, identity *authz.Identity, service string, req api.DataQueryRequest) (api.Response[api.DataQueryResult], error) {
	scope, backend, err := s.dataScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.DataQueryResult]{}, err
	}
	if strings.TrimSpace(req.Query) == "" {
		return api.Response[api.DataQueryResult]{}, apierr.InvalidRequest("query is required")
	}
	result, err := backend.query(ctx, req.Query, req.Variables)
	if err != nil {
		return api.Response[api.DataQueryResult]{}, err
	}
	data, err := shape.RedactJSON(s.redactor, result.data)
	if err != nil {
		return api.Response[api.DataQueryResult]{}, apierr.Upstream("data source returned invalid JSON: %v", err)
	}
	meta := api.Meta{
		Service:     scope.Service(),
		Environment: scope.Environment(),
		Sources:     []api.SourceRef{result.source},
		Untrusted:   dataUntrusted,
	}
	return api.Response[api.DataQueryResult]{Data: api.DataQueryResult{Query: result.query, Rows: result.rows, Data: data}, Meta: meta}, nil
}

// schemaCache keeps introspected schemas per source, project and stage.
type schemaCache struct {
	mu      sync.Mutex
	entries map[string]schemaEntry
	now     func() time.Time
}

type schemaEntry struct {
	schema  *gqlguard.Schema
	fetched time.Time
}

func newSchemaCache(now func() time.Time) *schemaCache {
	return &schemaCache{entries: map[string]schemaEntry{}, now: now}
}

// get returns a cached schema or loads a fresh one. Failed loads are not cached.
func (c *schemaCache) get(key string, load func() (*gqlguard.Schema, error)) (*gqlguard.Schema, error) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	if ok && c.now().Sub(entry.fetched) < schemaTTL {
		return entry.schema, nil
	}
	schema, err := load()
	if err != nil {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.entries[key] = schemaEntry{schema: schema, fetched: c.now()}
	c.mu.Unlock()
	return schema, nil
}
