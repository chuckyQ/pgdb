package parser

import (
	"fmt"
	"sort"
	"strings"
)

type Type struct {
	Name     string
	Abstract bool
	Fields   []*Field
}

func NewType(name string, abstract bool, fields []*Field) Type {
	return Type{
		Name:     name,
		Abstract: abstract,
		Fields:   fields,
	}
}

func (t *Type) FieldStr() string {
	fields := make([]string, 0, len(t.Fields))
	for _, field := range t.Fields {
		fields = append(fields, field.Name)
	}
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

func (t *Type) Diff(other *Type) (removed []string, added []*Field, same []string) {
	prevFields := make(map[string]struct{})
	newFields := make(map[string]struct{})

	for _, field := range t.Fields {
		prevFields[field.Name] = struct{}{}
	}

	for _, field := range other.Fields {
		newFields[field.Name] = struct{}{}
	}

	for name := range prevFields {
		if _, ok := newFields[name]; !ok {
			removed = append(removed, name)
		}
	}

	for name := range newFields {
		if _, ok := prevFields[name]; !ok {
			added = append(added, other.Get(name))
		}
	}

	for name := range prevFields {
		if _, ok := newFields[name]; ok {
			same = append(same, name)
		}
	}

	return
}

func (t *Type) Get(name string) *Field {
	for _, field := range t.Fields {
		if field.Name == name {
			return field
		}
	}

	panic(fmt.Sprintf(
		"Field %q is not in type %q?",
		name,
		t.Name,
	))
}

func (t *Type) String() string {
	return fmt.Sprintf(
		"Type(name=%q, fields=%v)",
		t.Name,
		t.Fields,
	)
}
