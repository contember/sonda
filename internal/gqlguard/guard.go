package gqlguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

// Rules restrict what a query may read and how much.
type Rules struct {
	// Entities is the allow list; empty allows every entity the role can read.
	Entities []string
	// Denied reports fields the agent may not select, filter, look up or order by.
	Denied func(entity, field string) bool
	// MaxRows caps the rows a query can return: the sum over every list and paginate field of
	// the product of the limits on its path.
	MaxRows int
	// MaxDepth caps the number of nested entity fields on a path.
	MaxDepth int
	// MaxFields caps the selected fields after fragments are inlined.
	MaxFields int
	// MaxOffset caps offset and skip.
	MaxOffset int
}

func (r Rules) allowed(entity string) bool {
	return len(r.Entities) == 0 || slices.Contains(r.Entities, entity)
}

func (r Rules) denied(entity, field string) bool {
	return r.Denied != nil && r.Denied(entity, field)
}

// Result is a checked query. Query is the normalized text: no fragments, no variables, no
// operation name. It is what runs upstream and what the audit log records.
type Result struct {
	Query  string
	Rows   int
	Depth  int
	Fields int
}

// Error is a rejection the agent can act on.
type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

func reject(format string, args ...any) error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}

// Check validates a query with its JSON variables against the schema and the rules.
func Check(s *Schema, query string, variables []byte, rules Rules) (Result, error) {
	if s.inverse == nil {
		// Without the relation model, a denied relation could be read from its other side.
		return Result{}, errors.New("schema has no relation model; call AddRelations")
	}
	vars, err := decodeVariables(variables)
	if err != nil {
		return Result{}, err
	}
	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil {
		return Result{}, reject("invalid GraphQL: %s", parseErrorMessage(parseErr))
	}
	// Validation has quadratic steps (overlapping fields), so the written fields are capped
	// before it runs. Fragment expansion is capped later, while printing.
	if rules.MaxFields > 0 && countFields(doc) > rules.MaxFields {
		return Result{}, reject("the query selects more than %d fields", rules.MaxFields)
	}
	if errs := validator.Validate(s.ast, doc); len(errs) > 0 {
		return Result{}, validationError(errs)
	}
	op, err := singleQuery(doc)
	if err != nil {
		return Result{}, err
	}
	normalized, err := normalize(s, op, vars, rules.MaxFields)
	if err != nil {
		return Result{}, err
	}
	// The normalized text is parsed and validated again, and the rules run on it, so what is
	// checked is exactly what is sent.
	final, errs := gqlparser.LoadQuery(s.ast, normalized)
	if len(errs) > 0 {
		return Result{}, fmt.Errorf("normalized query does not validate: %w (query: %s)", validationError(errs), normalized)
	}
	finalOp, err := singleQuery(final)
	if err != nil {
		return Result{}, fmt.Errorf("normalized query: %w", err)
	}
	w := &walker{schema: s, rules: rules}
	if err := w.root(finalOp.SelectionSet); err != nil {
		return Result{}, err
	}
	return Result{Query: normalized, Rows: w.rows, Depth: w.depth, Fields: w.fields}, nil
}

// countFields counts the fields written in the document, fragments counted once.
func countFields(doc *ast.QueryDocument) int {
	var count func(set ast.SelectionSet) int
	count = func(set ast.SelectionSet) int {
		n := 0
		for _, sel := range set {
			switch sel := sel.(type) {
			case *ast.Field:
				n += 1 + count(sel.SelectionSet)
			case *ast.InlineFragment:
				n += count(sel.SelectionSet)
			}
		}
		return n
	}
	total := 0
	for _, op := range doc.Operations {
		total += count(op.SelectionSet)
	}
	for _, f := range doc.Fragments {
		total += count(f.SelectionSet)
	}
	return total
}

func validationError(errs gqlerror.List) error {
	messages := make([]string, 0, min(len(errs), 3))
	for _, e := range errs[:min(len(errs), 3)] {
		messages = append(messages, e.Message)
	}
	return reject("invalid GraphQL: %s", strings.Join(messages, "; "))
}

func decodeVariables(data []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 || string(bytes.TrimSpace(data)) == "null" {
		return map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var vars map[string]any
	if err := decoder.Decode(&vars); err != nil {
		return nil, reject("variables must be a JSON object: %v", err)
	}
	if decoder.More() {
		return nil, reject("variables must be a single JSON object")
	}
	return vars, nil
}

// singleQuery requires exactly one query operation and no directives anywhere.
func singleQuery(doc *ast.QueryDocument) (*ast.OperationDefinition, error) {
	if len(doc.Operations) != 1 {
		return nil, reject("the document must contain exactly one operation, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	if op.Operation != ast.Query {
		return nil, reject("only query operations are allowed, got %s", op.Operation)
	}
	if len(op.Directives) > 0 {
		return nil, reject("directives are not allowed")
	}
	for _, v := range op.VariableDefinitions {
		if len(v.Directives) > 0 {
			return nil, reject("directives are not allowed")
		}
	}
	for _, f := range doc.Fragments {
		if len(f.Directives) > 0 {
			return nil, reject("directives are not allowed")
		}
	}
	return op, nil
}

// normalize prints the operation with fragments and variables inlined.
func normalize(s *Schema, op *ast.OperationDefinition, vars map[string]any, maxFields int) (string, error) {
	for name := range vars {
		if op.VariableDefinitions.ForName(name) == nil {
			return "", reject("variable $%s is not defined in the query", name)
		}
	}
	p := &printer{schema: s, vars: vars, maxFields: maxFields}
	p.b.WriteString("query ")
	if err := p.selectionSet(op.SelectionSet, s.ast.Query.Name); err != nil {
		return "", err
	}
	return p.b.String(), nil
}

type printer struct {
	schema    *Schema
	vars      map[string]any
	b         strings.Builder
	fields    int
	maxFields int
}

func (p *printer) selectionSet(set ast.SelectionSet, parent string) error {
	p.b.WriteString("{ ")
	if err := p.selections(set, parent); err != nil {
		return err
	}
	p.b.WriteString("}")
	return nil
}

func (p *printer) selections(set ast.SelectionSet, parent string) error {
	for _, sel := range set {
		switch sel := sel.(type) {
		case *ast.Field:
			if err := p.field(sel); err != nil {
				return err
			}
		case *ast.FragmentSpread:
			if len(sel.Directives) > 0 {
				return reject("directives are not allowed")
			}
			// Contember has no interfaces or unions, so a fragment applies only to its own type.
			if sel.Definition.TypeCondition != parent {
				return reject("fragment %s on %s is spread inside %s", sel.Name, sel.Definition.TypeCondition, parent)
			}
			if err := p.selections(sel.Definition.SelectionSet, parent); err != nil {
				return err
			}
		case *ast.InlineFragment:
			if len(sel.Directives) > 0 {
				return reject("directives are not allowed")
			}
			if sel.TypeCondition != "" && sel.TypeCondition != parent {
				return reject("inline fragment on %s inside %s", sel.TypeCondition, parent)
			}
			if err := p.selections(sel.SelectionSet, parent); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown selection %T", sel)
		}
	}
	return nil
}

func (p *printer) field(f *ast.Field) error {
	if len(f.Directives) > 0 {
		return reject("directives are not allowed")
	}
	// Fragments can multiply fields exponentially, so the budget is checked while printing.
	p.fields++
	if p.maxFields > 0 && p.fields > p.maxFields {
		return reject("the query selects more than %d fields", p.maxFields)
	}
	if f.Alias != "" && f.Alias != f.Name {
		p.b.WriteString(f.Alias + ": ")
	}
	p.b.WriteString(f.Name)
	var args []string
	for _, arg := range f.Arguments {
		text, ok, err := p.value(arg.Value)
		if err != nil {
			return err
		}
		if ok {
			args = append(args, arg.Name+": "+text)
		}
	}
	if len(args) > 0 {
		p.b.WriteString("(" + strings.Join(args, ", ") + ")")
	}
	p.b.WriteString(" ")
	if len(f.SelectionSet) > 0 {
		if err := p.selectionSet(f.SelectionSet, f.Definition.Type.Name()); err != nil {
			return err
		}
		p.b.WriteString(" ")
	}
	return nil
}

// value prints a literal. ok is false for a variable without a value and without a default:
// GraphQL treats such an argument or object field as not given.
func (p *printer) value(v *ast.Value) (text string, ok bool, err error) {
	switch v.Kind {
	case ast.Variable:
		def := v.VariableDefinition
		if val, given := p.vars[v.Raw]; given {
			text, err := p.literal(val, def.Type)
			return text, err == nil, err
		}
		if def.DefaultValue != nil {
			return p.value(def.DefaultValue)
		}
		if def.Type.NonNull {
			return "", false, reject("variable $%s is required", v.Raw)
		}
		return "", false, nil
	case ast.IntValue, ast.FloatValue, ast.BooleanValue, ast.EnumValue:
		return v.Raw, true, nil
	case ast.NullValue:
		return "null", true, nil
	case ast.StringValue, ast.BlockValue:
		return quote(v.Raw), true, nil
	case ast.ListValue:
		items := make([]string, 0, len(v.Children))
		for _, child := range v.Children {
			text, ok, err := p.value(child.Value)
			if err != nil {
				return "", false, err
			}
			if !ok {
				text = "null"
			}
			items = append(items, text)
		}
		return "[" + strings.Join(items, ", ") + "]", true, nil
	case ast.ObjectValue:
		fields := make([]string, 0, len(v.Children))
		for _, child := range v.Children {
			text, ok, err := p.value(child.Value)
			if err != nil {
				return "", false, err
			}
			if ok {
				fields = append(fields, child.Name+": "+text)
			}
		}
		return "{" + strings.Join(fields, ", ") + "}", true, nil
	}
	return "", false, fmt.Errorf("unknown value kind %d", v.Kind)
}

// literal prints a JSON variable value as a literal of the given type. The result is
// validated again with the rest of the normalized query.
func (p *printer) literal(val any, t *ast.Type) (string, error) {
	if val == nil {
		return "null", nil
	}
	if t.Elem != nil {
		list, isList := val.([]any)
		if !isList {
			// Input coercion: a single value stands for a list of one.
			text, err := p.literal(val, t.Elem)
			return "[" + text + "]", err
		}
		items := make([]string, len(list))
		for i, item := range list {
			text, err := p.literal(item, t.Elem)
			if err != nil {
				return "", err
			}
			items[i] = text
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	}
	def := p.schema.ast.Types[t.NamedType]
	if def == nil {
		return "", fmt.Errorf("unknown type %s", t.NamedType)
	}
	switch def.Kind {
	case ast.Enum:
		name, isString := val.(string)
		if !isString || def.EnumValues.ForName(name) == nil {
			return "", reject("value %v is not a value of enum %s", val, def.Name)
		}
		return name, nil
	case ast.InputObject:
		obj, isObject := val.(map[string]any)
		if !isObject {
			return "", reject("value of type %s must be an object", def.Name)
		}
		fields := make([]string, 0, len(obj))
		for _, name := range sortedKeys(obj) {
			field := def.Fields.ForName(name)
			if field == nil {
				return "", reject("input %s has no field %s", def.Name, name)
			}
			text, err := p.literal(obj[name], field.Type)
			if err != nil {
				return "", err
			}
			fields = append(fields, name+": "+text)
		}
		return "{" + strings.Join(fields, ", ") + "}", nil
	case ast.Scalar:
		return scalarLiteral(val, def.Name)
	}
	return "", reject("type %s is not an input type", def.Name)
}

func scalarLiteral(val any, typeName string) (string, error) {
	switch v := val.(type) {
	case string:
		return quote(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case json.Number:
		if typeName == "Int" {
			if _, err := v.Int64(); err != nil {
				return "", reject("value %s is not an Int", v)
			}
		}
		return v.String(), nil
	}
	// Objects and lists for custom scalars (e.g. Json) are not needed for reading.
	return "", reject("value of scalar %s must be a string, number or boolean", typeName)
}

// quote prints a GraphQL string. JSON string syntax is valid GraphQL string syntax.
func quote(s string) string {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// walker checks the rules on the normalized, validated query.
type walker struct {
	schema *Schema
	rules  Rules
	rows   int
	depth  int
	fields int
}

// hop describes a field that returns rows of an entity.
type hop struct {
	target     string
	connection bool
	// limitArg is the argument that sets the row count of a list: limit or first.
	limitArg string
}

func (w *walker) countField() error {
	w.fields++
	if w.rules.MaxFields > 0 && w.fields > w.rules.MaxFields {
		return reject("the query selects more than %d fields", w.rules.MaxFields)
	}
	return nil
}

func (w *walker) root(set ast.SelectionSet) error {
	for _, sel := range set {
		f, ok := sel.(*ast.Field)
		if !ok {
			return errors.New("normalized query contains a fragment")
		}
		if err := w.countField(); err != nil {
			return err
		}
		if f.Name == "__typename" {
			continue
		}
		if strings.HasPrefix(f.Name, "__") {
			return reject("introspection (%s) is not allowed; use the data schema endpoint", f.Name)
		}
		t := f.Definition.Type
		named := t.Name()
		var h hop
		switch {
		case w.schema.entities[named] != nil && t.Elem == nil && f.Name == "get"+named:
			h = hop{target: named}
		case w.schema.entities[named] != nil && t.Elem != nil && f.Name == "list"+named:
			h = hop{target: named, limitArg: "limit"}
		case w.schema.connections[named] != "" && f.Name == "paginate"+w.schema.connections[named]:
			h = hop{target: w.schema.connections[named], connection: true, limitArg: "first"}
		default:
			return reject("root field %s is not allowed; use get<Entity>, list<Entity> or paginate<Entity>", f.Name)
		}
		if err := w.hop(f, h, 1, 0); err != nil {
			return err
		}
	}
	return nil
}

// hop checks a field that returns rows of an entity and descends into its selection.
func (w *walker) hop(f *ast.Field, h hop, multiplier, depth int) error {
	if !w.rules.allowed(h.target) {
		return reject("entity %s is not allowed", h.target)
	}
	depth++
	if w.rules.MaxDepth > 0 && depth > w.rules.MaxDepth {
		return reject("the query nests more than %d entity levels", w.rules.MaxDepth)
	}
	w.depth = max(w.depth, depth)
	rows := 1
	hasLimit := false
	for _, arg := range f.Arguments {
		switch arg.Name {
		case "filter":
			if err := w.where(arg.Value, h.target); err != nil {
				return err
			}
		case "by":
			if err := w.unique(arg.Value, h.target); err != nil {
				return err
			}
		case "orderBy":
			if err := w.orderBy(arg.Value, h.target); err != nil {
				return err
			}
		case "limit", "first":
			if arg.Name != h.limitArg {
				return reject("argument %s is not supported on %s", arg.Name, f.Name)
			}
			n, err := intArg(f.Name, arg)
			if err != nil {
				return err
			}
			rows, hasLimit = n, true
		case "offset", "skip":
			n, err := intArg(f.Name, arg)
			if err != nil {
				return err
			}
			if w.rules.MaxOffset > 0 && n > w.rules.MaxOffset {
				return reject("%s on %s is %d, the maximum is %d", arg.Name, f.Name, n, w.rules.MaxOffset)
			}
		default:
			return reject("argument %s is not supported on %s", arg.Name, f.Name)
		}
	}
	if h.limitArg != "" && !hasLimit {
		return reject("%s needs %s: N (at most %d rows per query)", f.Name, h.limitArg, w.rules.MaxRows)
	}
	// A list multiplies the rows of everything below it; a single row (get, has-one, <rel>By)
	// adds nothing on its own.
	multiplier *= rows
	if h.limitArg != "" {
		w.rows += multiplier
	}
	if w.rules.MaxRows > 0 && (rows > w.rules.MaxRows || w.rows > w.rules.MaxRows) {
		return reject("the query can return %d rows, the limit is %d; lower the limits of nested lists", w.rows, w.rules.MaxRows)
	}
	if h.connection {
		return w.connection(f.SelectionSet, h.target, multiplier, depth)
	}
	return w.entity(f.SelectionSet, h.target, multiplier, depth)
}

func intArg(field string, arg *ast.Argument) (int, error) {
	if arg.Value.Kind != ast.IntValue {
		return 0, reject("%s on %s must be an integer", arg.Name, field)
	}
	n, err := strconv.Atoi(arg.Value.Raw)
	if err != nil || n < 0 {
		return 0, reject("%s on %s must be a non-negative integer", arg.Name, field)
	}
	return n, nil
}

func (w *walker) entity(set ast.SelectionSet, name string, multiplier, depth int) error {
	e := w.schema.entities[name]
	for _, sel := range set {
		f := sel.(*ast.Field)
		if err := w.countField(); err != nil {
			return err
		}
		switch {
		case f.Name == "__typename":
		case e.columns[f.Name] != nil:
			if w.schema.denied(w.rules, name, f.Name) {
				return reject("field %s.%s is not allowed", name, f.Name)
			}
			if len(f.Arguments) > 0 {
				return reject("arguments on %s.%s are not supported", name, f.Name)
			}
		case e.relations[f.Name] != (relation{}):
			r := e.relations[f.Name]
			if w.schema.denied(w.rules, name, f.Name) {
				return reject("field %s.%s is not allowed", name, f.Name)
			}
			h := hop{target: r.target}
			if r.many {
				h.limitArg = "limit"
			}
			if err := w.hop(f, h, multiplier, depth); err != nil {
				return err
			}
		case e.derived[f.Name] != "":
			base := e.derived[f.Name]
			if w.schema.denied(w.rules, name, base) {
				return reject("field %s.%s is not allowed", name, base)
			}
			named := f.Definition.Type.Name()
			h := hop{target: named}
			if target := w.schema.connections[named]; target != "" {
				h = hop{target: target, connection: true, limitArg: "first"}
			}
			if err := w.hop(f, h, multiplier, depth); err != nil {
				return err
			}
		default:
			return reject("field %s.%s is not supported", name, f.Name)
		}
	}
	return nil
}

func (w *walker) connection(set ast.SelectionSet, name string, multiplier, depth int) error {
	for _, sel := range set {
		f := sel.(*ast.Field)
		if err := w.countField(); err != nil {
			return err
		}
		switch f.Name {
		case "__typename":
		case "pageInfo":
			for _, sub := range f.SelectionSet {
				pf := sub.(*ast.Field)
				if err := w.countField(); err != nil {
					return err
				}
				if pf.Name != "totalCount" && pf.Name != "__typename" {
					return reject("field pageInfo.%s is not supported", pf.Name)
				}
			}
		case "edges":
			for _, sub := range f.SelectionSet {
				ef := sub.(*ast.Field)
				if err := w.countField(); err != nil {
					return err
				}
				switch ef.Name {
				case "__typename":
				case "node":
					if err := w.entity(ef.SelectionSet, name, multiplier, depth); err != nil {
						return err
					}
				default:
					return reject("field edges.%s is not supported", ef.Name)
				}
			}
		default:
			return reject("field %s is not supported on a connection", f.Name)
		}
	}
	return nil
}

// where checks a filter: every field it compares, also through relations and and/or/not,
// must be readable, so a filter cannot test values of a denied field.
func (w *walker) where(v *ast.Value, entityName string) error {
	return w.input(v, entityName, "filter", func(key string) bool { return key == "and" || key == "or" || key == "not" })
}

// unique checks a unique lookup (by), which reveals whether a record with a value exists.
func (w *walker) unique(v *ast.Value, entityName string) error {
	return w.input(v, entityName, "by", func(string) bool { return false })
}

// orderBy checks the ordering, which can reveal values of a field by binary search.
func (w *walker) orderBy(v *ast.Value, entityName string) error {
	return w.input(v, entityName, "orderBy", func(key string) bool { return key == "_random" || key == "_randomSeeded" })
}

// input walks an entity input object (where, unique where, order by). Keys are fields of the
// entity, or operators that keep the same entity. Relations descend into their target entity.
// Condition values of columns hold no entity fields.
func (w *walker) input(v *ast.Value, entityName, kind string, operator func(string) bool) error {
	switch v.Kind {
	case ast.NullValue:
		return nil
	case ast.ListValue:
		for _, child := range v.Children {
			if err := w.input(child.Value, entityName, kind, operator); err != nil {
				return err
			}
		}
		return nil
	case ast.ObjectValue:
	default:
		return reject("%s on %s must be an object", kind, entityName)
	}
	e := w.schema.entities[entityName]
	for _, child := range v.Children {
		key := child.Name
		switch {
		case operator(key):
			if key == "_random" || key == "_randomSeeded" {
				continue
			}
			if err := w.input(child.Value, entityName, kind, operator); err != nil {
				return err
			}
		case e.columns[key] != nil:
			if w.schema.denied(w.rules, entityName, key) {
				return reject("field %s.%s is not allowed in %s", entityName, key, kind)
			}
		case e.relations[key] != (relation{}):
			r := e.relations[key]
			if w.schema.denied(w.rules, entityName, key) {
				return reject("field %s.%s is not allowed in %s", entityName, key, kind)
			}
			if !w.rules.allowed(r.target) {
				return reject("entity %s is not allowed (in %s of %s.%s)", r.target, kind, entityName, key)
			}
			if err := w.input(child.Value, r.target, kind, operator); err != nil {
				return err
			}
		default:
			return reject("%s field %s.%s is not supported", kind, entityName, key)
		}
	}
	return nil
}

func parseErrorMessage(err error) string {
	var gqlErr *gqlerror.Error
	if errors.As(err, &gqlErr) {
		return gqlErr.Message
	}
	return err.Error()
}
