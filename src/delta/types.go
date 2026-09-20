package delta

import (
	"fmt"

	"github.com/chuckyQ/pgdb/parser"
)

type TypesDelta struct {
	TypName string
	Removed []string
	Added   []*parser.Field
	Deltas  []*TypeDelta
}

func NewTypesDelta(
	typName string,
	removed []string,
	added []*parser.Field,
	deltas []*TypeDelta,
) *TypesDelta {
	return &TypesDelta{
		TypName: typName,
		Removed: removed,
		Added:   added,
		Deltas:  deltas,
	}
}

func (t *TypesDelta) ToSQL() []string {
	queries := make([]string, 0)

	for _, name := range t.Removed {
		queries = append(
			queries,
			fmt.Sprintf(
				"ALTER TABLE %s DROP COLUMN %s;",
				t.TypName,
				name,
			),
		)
	}

	for _, field := range t.Added {
		queries = append(
			queries,
			fmt.Sprintf(
				"ALTER TABLE %s ADD COLUMN %s %s;",
				t.TypName,
				field.Name,
				field.Typ,
			),
		)
	}

	for _, delta := range t.Deltas {
		queries = append(
			queries,
			delta.ToSQL()...,
		)
	}

	return queries
}
