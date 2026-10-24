package gqlguard

import (
	"fmt"
	"slices"
	"strings"
)

// introspection is the result of the standard introspection query. It is printed as SDL,
// because the parser loads schemas only from SDL.
type introspection struct {
	Schema *introspectionSchema `json:"__schema"`
}

type introspectionSchema struct {
	QueryType        *namedRef           `json:"queryType"`
	MutationType     *namedRef           `json:"mutationType"`
	SubscriptionType *namedRef           `json:"subscriptionType"`
	Types            []introspectionType `json:"types"`
}

type namedRef struct {
	Name string `json:"name"`
}

type introspectionType struct {
	Kind          string               `json:"kind"`
	Name          string               `json:"name"`
	Fields        []introspectionField `json:"fields"`
	InputFields   []introspectionInput `json:"inputFields"`
	Interfaces    []typeRef            `json:"interfaces"`
	EnumValues    []namedRef           `json:"enumValues"`
	PossibleTypes []typeRef            `json:"possibleTypes"`
}

type introspectionField struct {
	Name string               `json:"name"`
	Args []introspectionInput `json:"args"`
	Type typeRef              `json:"type"`
}

type introspectionInput struct {
	Name         string  `json:"name"`
	Type         typeRef `json:"type"`
	DefaultValue *string `json:"defaultValue"`
}

type typeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *typeRef `json:"ofType"`
}

func (t typeRef) String() string {
	switch t.Kind {
	case "NON_NULL":
		if t.OfType != nil {
			return t.OfType.String() + "!"
		}
	case "LIST":
		if t.OfType != nil {
			return "[" + t.OfType.String() + "]"
		}
	}
	return t.Name
}

var builtinScalars = []string{"String", "Int", "Float", "Boolean", "ID"}

// sdl prints the types of the schema. Directive definitions are left out: queries with
// directives are rejected anyway.
func (s *introspectionSchema) sdl() (string, error) {
	var b strings.Builder
	b.WriteString("schema {\n  query: " + s.QueryType.Name + "\n")
	if s.MutationType != nil {
		b.WriteString("  mutation: " + s.MutationType.Name + "\n")
	}
	if s.SubscriptionType != nil {
		b.WriteString("  subscription: " + s.SubscriptionType.Name + "\n")
	}
	b.WriteString("}\n")
	for _, t := range s.Types {
		if strings.HasPrefix(t.Name, "__") || (t.Kind == "SCALAR" && slices.Contains(builtinScalars, t.Name)) {
			continue
		}
		switch t.Kind {
		case "SCALAR":
			fmt.Fprintf(&b, "scalar %s\n", t.Name)
		case "OBJECT", "INTERFACE":
			keyword := "type"
			if t.Kind == "INTERFACE" {
				keyword = "interface"
			}
			b.WriteString(keyword + " " + t.Name)
			if len(t.Interfaces) > 0 {
				names := make([]string, len(t.Interfaces))
				for i, iface := range t.Interfaces {
					names[i] = iface.Name
				}
				b.WriteString(" implements " + strings.Join(names, " & "))
			}
			b.WriteString(" {\n")
			for _, f := range t.Fields {
				b.WriteString("  " + f.Name + arguments(f.Args) + ": " + f.Type.String() + "\n")
			}
			b.WriteString("}\n")
		case "UNION":
			names := make([]string, len(t.PossibleTypes))
			for i, p := range t.PossibleTypes {
				names[i] = p.Name
			}
			fmt.Fprintf(&b, "union %s = %s\n", t.Name, strings.Join(names, " | "))
		case "ENUM":
			b.WriteString("enum " + t.Name + " {\n")
			for _, v := range t.EnumValues {
				b.WriteString("  " + v.Name + "\n")
			}
			b.WriteString("}\n")
		case "INPUT_OBJECT":
			b.WriteString("input " + t.Name + " {\n")
			for _, f := range t.InputFields {
				b.WriteString("  " + inputValue(f) + "\n")
			}
			b.WriteString("}\n")
		default:
			return "", fmt.Errorf("introspection type %s has unknown kind %q", t.Name, t.Kind)
		}
	}
	return b.String(), nil
}

func arguments(args []introspectionInput) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = inputValue(a)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func inputValue(in introspectionInput) string {
	s := in.Name + ": " + in.Type.String()
	if in.DefaultValue != nil {
		s += " = " + *in.DefaultValue
	}
	return s
}
