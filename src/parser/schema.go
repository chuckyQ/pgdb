package parser

import "fmt"

type Schema struct {
	Types []Type
}

func NewSchema(types []Type) *Schema {
	return &Schema{
		Types: types,
	}
}

func (s *Schema) Diff(other Schema) (removed []string, added []*Type, same []string) {

	prevTypes := make(map[string]struct{})
	newTypes := make(map[string]struct{})

	for _, typ := range s.Types {
		prevTypes[typ.Name] = struct{}{}
	}

	for _, typ := range other.Types {
		newTypes[typ.Name] = struct{}{}
	}

	for name := range prevTypes {
		if _, ok := newTypes[name]; !ok {
			removed = append(removed, name)
		}
	}

	for name := range newTypes {
		if _, ok := prevTypes[name]; !ok {
			added = append(added, other.Get(name))
		}
	}

	for name := range prevTypes {
		if _, ok := newTypes[name]; ok {
			same = append(same, name)
		}
	}

	return
}

func (s *Schema) Get(name string) *Type {
	for _, typ := range s.Types {
		if typ.Name == name {
			return &typ
		}
	}

	panic(fmt.Sprintf(
		"type %q is not in schema",
		name,
	))
}
