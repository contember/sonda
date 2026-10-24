// Package gqlguard checks agent-written GraphQL against a Contember Content API schema.
// It parses and validates the query, inlines fragments and variables into one normalized
// query, validates that text again and checks it against read-only rules: only get, list and
// paginate root fields, allowed entities, denied fields (also in filters, unique lookups and
// ordering), required row limits, and depth, field and row budgets.
package gqlguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

// Schema is a Contember Content API schema as one API key's role sees it.
type Schema struct {
	ast         *ast.Schema
	entities    map[string]*entity
	connections map[string]string // connection type → entity
	edges       map[string]string // edge type → entity
	pageInfo    string
	write       []string
	// inverse maps "Entity.relation" to the other side of the relation, "Target.field".
	// It is nil until AddRelations runs.
	inverse map[string]string
}

type entity struct {
	name      string
	fields    []string // columns and relations in schema order
	columns   map[string]*ast.Type
	relations map[string]relation
	// derived maps paginate<Rel> and <rel>By… fields to their has-many relation.
	derived map[string]string
	unique  []string
}

type relation struct {
	target string
	many   bool
}

// LoadIntrospection builds a Schema from the JSON result of a standard introspection query.
// It accepts the full GraphQL response ({"data": {"__schema": …}}) or the data object.
func LoadIntrospection(data []byte) (*Schema, error) {
	var envelope struct {
		Data *introspection `json:"data"`
		introspection
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("invalid introspection JSON: %w", err)
	}
	in := &envelope.introspection
	if envelope.Data != nil {
		in = envelope.Data
	}
	if in.Schema == nil || in.Schema.QueryType == nil {
		return nil, errors.New("introspection result has no __schema.queryType")
	}
	sdl, err := in.Schema.sdl()
	if err != nil {
		return nil, err
	}
	parsed, err := gqlparser.LoadSchema(&ast.Source{Name: "introspection", Input: sdl})
	if err != nil {
		return nil, fmt.Errorf("introspected schema does not load: %w", err)
	}
	s := &Schema{
		ast:         parsed,
		entities:    map[string]*entity{},
		connections: map[string]string{},
		edges:       map[string]string{},
	}
	s.classify()
	return s, nil
}

// classify finds entities, their connection and edge types, and fields that can write.
func (s *Schema) classify() {
	query := s.ast.Query
	// An entity X is an object type that the root lists as list<X>: [X!]!.
	for _, field := range query.Fields {
		name, ok := strings.CutPrefix(field.Name, "list")
		if !ok || field.Type.Elem == nil || field.Type.Elem.NamedType != name {
			continue
		}
		if def := s.ast.Types[name]; def != nil && def.Kind == ast.Object {
			s.entities[name] = &entity{name: name, columns: map[string]*ast.Type{}, relations: map[string]relation{}, derived: map[string]string{}}
		}
	}
	for name := range s.entities {
		if field := query.Fields.ForName("paginate" + name); field != nil && field.Type.Elem == nil {
			s.connection(field.Type.Name(), name)
		}
		if field := query.Fields.ForName("get" + name); field != nil {
			if by := field.Arguments.ForName("by"); by != nil {
				s.entities[name].unique = s.uniqueKeys(by.Type.Name())
			}
		}
	}
	for _, e := range s.entities {
		s.entityFields(e)
	}
	if s.ast.Mutation != nil {
		for _, field := range s.ast.Mutation.Fields {
			if !strings.HasPrefix(field.Name, "__") {
				s.write = append(s.write, "Mutation."+field.Name)
			}
		}
	}
	// Validation queries exist only for roles that may create or update.
	for _, field := range query.Fields {
		if strings.HasPrefix(field.Name, "validateCreate") || strings.HasPrefix(field.Name, "validateUpdate") {
			s.write = append(s.write, "Query."+field.Name)
		}
	}
	sort.Strings(s.write)
}

func (s *Schema) connection(typeName, entityName string) {
	def := s.ast.Types[typeName]
	if def == nil || def.Kind != ast.Object {
		return
	}
	edges, pageInfo := def.Fields.ForName("edges"), def.Fields.ForName("pageInfo")
	if edges == nil || pageInfo == nil {
		return
	}
	edge := s.ast.Types[edges.Type.Name()]
	if edge == nil || edge.Fields.ForName("node") == nil || edge.Fields.ForName("node").Type.Name() != entityName {
		return
	}
	s.connections[typeName] = entityName
	s.edges[edge.Name] = entityName
	s.pageInfo = pageInfo.Type.Name()
}

// uniqueKeys reads the fields of an entity's unique-where input. Each belongs to a unique
// constraint; a composite constraint needs all of its fields.
func (s *Schema) uniqueKeys(typeName string) []string {
	def := s.ast.Types[typeName]
	if def == nil {
		return nil
	}
	var keys []string
	for _, field := range def.Fields {
		keys = append(keys, field.Name)
	}
	return keys
}

func (s *Schema) entityFields(e *entity) {
	def := s.ast.Types[e.name]
	var pending []*ast.FieldDefinition
	for _, field := range def.Fields {
		named := field.Type.Name()
		switch {
		case strings.HasPrefix(field.Name, "__") || field.Name == "_meta":
		case s.entities[named] != nil && field.Arguments.ForName("by") == nil:
			e.relations[field.Name] = relation{target: named, many: field.Type.Elem != nil}
			e.fields = append(e.fields, field.Name)
		case s.entities[named] != nil || s.connections[named] != "":
			pending = append(pending, field)
		case s.isLeaf(named):
			e.columns[field.Name] = field.Type
			e.fields = append(e.fields, field.Name)
		}
	}
	// Derived fields are paginate<Rel> and the has-many-to-has-one reducers <rel>By, <rel>By<Key>.
	for _, field := range pending {
		if base := e.derivedBase(field.Name, s.connections[field.Type.Name()] != ""); base != "" {
			e.derived[field.Name] = base
		}
	}
}

func (e *entity) derivedBase(name string, connection bool) string {
	best := ""
	for rel, r := range e.relations {
		if !r.many {
			continue
		}
		if connection && name == "paginate"+upperFirst(rel) {
			return rel
		}
		if !connection && strings.HasPrefix(name, rel+"By") && len(rel) > len(best) {
			best = rel
		}
	}
	return best
}

// AddRelations reads the relation model from the Content API's schema root field:
//
//	query { schema { entities { name fields { name ... on _Relation { targetEntity ownedBy inversedBy } } } } }
//
// A relation can be read from both sides, so a denied relation also denies its other side.
func (s *Schema) AddRelations(data []byte) error {
	var envelope struct {
		Data *relationModel `json:"data"`
		relationModel
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("invalid relation model JSON: %w", err)
	}
	model := &envelope.relationModel
	if envelope.Data != nil {
		model = envelope.Data
	}
	if model.Schema == nil {
		return errors.New("relation model has no schema field")
	}
	s.inverse = map[string]string{}
	for _, e := range model.Schema.Entities {
		for _, f := range e.Fields {
			other := f.OwnedBy
			if other == "" {
				other = f.InversedBy
			}
			if f.TargetEntity != "" && other != "" {
				s.inverse[e.Name+"."+f.Name] = f.TargetEntity + "." + other
			}
		}
	}
	return nil
}

type relationModel struct {
	Schema *struct {
		Entities []struct {
			Name   string `json:"name"`
			Fields []struct {
				Name         string `json:"name"`
				TargetEntity string `json:"targetEntity"`
				OwnedBy      string `json:"ownedBy"`
				InversedBy   string `json:"inversedBy"`
			} `json:"fields"`
		} `json:"entities"`
	} `json:"schema"`
}

// denied applies the rules to a field and, for a relation, to its other side.
func (s *Schema) denied(rules Rules, entity, field string) bool {
	if rules.denied(entity, field) {
		return true
	}
	other, ok := s.inverse[entity+"."+field]
	if !ok {
		return false
	}
	target, name, _ := strings.Cut(other, ".")
	return rules.denied(target, name)
}

func (s *Schema) isLeaf(name string) bool {
	def := s.ast.Types[name]
	return def != nil && (def.Kind == ast.Scalar || def.Kind == ast.Enum)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// WriteFields lists fields that exist only for a role that can write: every Mutation field
// and the validateCreate/validateUpdate queries. A read-only role has none.
func (s *Schema) WriteFields() []string { return slices.Clone(s.write) }

// HasEntity reports whether the role can read the entity.
func (s *Schema) HasEntity(name string) bool { return s.entities[name] != nil }

// HasField reports whether the entity has a column or relation of that name.
func (s *Schema) HasField(entityName, field string) bool {
	e := s.entities[entityName]
	return e != nil && (e.columns[field] != nil || e.relations[field] != (relation{}))
}

// EntityNames returns the readable entities, sorted.
func (s *Schema) EntityNames() []string {
	names := make([]string, 0, len(s.entities))
	for name := range s.entities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Entity is the compact description of one entity.
type Entity struct {
	Name   string
	Fields []Field
	// Unique lists the fields usable in get<E>(by: …).
	Unique []string
}

// Field is a column (Type set) or a relation (Target set).
type Field struct {
	Name     string
	Type     string
	Nullable bool
	List     bool
	Target   string
	Many     bool
}

// Visible returns the entities and fields the rules let an agent see, sorted by entity name,
// and the enums those fields use.
func (s *Schema) Visible(rules Rules) ([]Entity, map[string][]string) {
	var result []Entity
	enums := map[string][]string{}
	for _, name := range s.EntityNames() {
		if !rules.allowed(name) {
			continue
		}
		e := s.entities[name]
		out := Entity{Name: name}
		for _, field := range e.fields {
			if s.denied(rules, name, field) {
				continue
			}
			if r, ok := e.relations[field]; ok {
				if rules.allowed(r.target) {
					out.Fields = append(out.Fields, Field{Name: field, Target: r.target, Many: r.many})
				}
				continue
			}
			t := e.columns[field]
			named := t.Name()
			out.Fields = append(out.Fields, Field{Name: field, Type: named, Nullable: !t.NonNull, List: t.Elem != nil})
			if def := s.ast.Types[named]; def.Kind == ast.Enum {
				values := make([]string, len(def.EnumValues))
				for i, v := range def.EnumValues {
					values[i] = v.Name
				}
				enums[named] = values
			}
		}
		for _, key := range e.unique {
			r, isRelation := e.relations[key]
			if !s.denied(rules, name, key) && (!isRelation || rules.allowed(r.target)) {
				out.Unique = append(out.Unique, key)
			}
		}
		result = append(result, out)
	}
	return result, enums
}
