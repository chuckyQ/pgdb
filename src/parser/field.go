package parser

import "fmt"

type Field struct {
	Name     string
	Typ      string
	Required bool
}

func NewField(name string, required bool, typ string) Field {
	return Field{
		Name:     name,
		Typ:      typ,
		Required: required,
	}
}

func (f *Field) Diff(other *Field) (nameChanged bool, typeChanged bool) {
	return f.Name != other.Name, f.Typ != other.Typ
}

func (f *Field) Equal(other *Field) bool {
	return f.Name == other.Name && f.Typ == other.Typ
}

func (f Field) String() string {
	return fmt.Sprintf(
		"Field(name=%q, required=%t, typ=%q)",
		f.Name,
		f.Required,
		f.Typ,
	)
}
