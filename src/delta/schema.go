package delta

import (
	"fmt"
	"strings"

	"github.com/chuckyQ/pgdb/parser"
)

type SchemaDelta struct {
	Removed []string
	Added   []*parser.Type
	Renamed map[string]string
}

func NewSchemaDelta(removed []string, added []*parser.Type, renamed map[string]string) *SchemaDelta {
	return &SchemaDelta{
		Removed: removed,
		Added:   added,
		Renamed: renamed,
	}
}

func (s *SchemaDelta) ToSQL() []string {
	queries := make([]string, 0)

	for _, name := range s.Removed {
		queries = append(
			queries,
			fmt.Sprintf("DROP TABLE %s;", name),
		)
	}

	for _, typ := range s.Added {
		values := make([]string, 0, len(typ.Fields))

		for _, field := range typ.Fields {
			values = append(
				values,
				fmt.Sprintf("%s %s", field.Name, field.Typ),
			)
		}

		queries = append(
			queries,
			fmt.Sprintf(
				"CREATE TABLE %s(%s);",
				typ.Name,
				strings.Join(values, ", "),
			),
		)
	}

	for prev, newName := range s.Renamed {
		queries = append(
			queries,
			fmt.Sprintf(
				"ALTER TABLE %s RENAME TO %s;",
				prev,
				newName,
			),
		)
	}

	return queries
}

func DiffSchemas(schema1 parser.Schema, schema2 parser.Schema) (*SchemaDelta, []*TypesDelta, error) {

	removedTypes, addedTypes, sameTypes := schema1.Diff(schema2)

	renamedTypes := make(map[string]string)

	addedNames := make([]string, 0, len(addedTypes))

	for _, typ := range addedTypes {
		addedNames = append(addedNames, typ.Name)
	}

	for _, oldName := range removedTypes {
		if _, ok := renamedTypes[oldName]; ok {
			continue
		}

		// Find similar table names.
		closeMatches := GetCloseMatches(
			oldName,
			addedNames,
			3,
		)

		// Find similar field layouts.
		oldType := schema1.Get(oldName)

		bodies := make(map[string]string)

		for _, typ := range addedTypes {
			bodies[typ.FieldStr()] = typ.Name
		}

		bodyStrings := make([]string, 0, len(bodies))

		for body := range bodies {
			bodyStrings = append(bodyStrings, body)
		}

		closeBodies := GetCloseMatches(
			oldType.FieldStr(),
			bodyStrings,
			3,
		)

		closeTypes := make([]string, 0)

		for _, body := range closeBodies {
			closeTypes = append(
				closeTypes,
				bodies[body],
			)
		}

		candidates := append(closeMatches, closeTypes...)

		for _, newName := range candidates {
			ok, err := GetYesNo(
				fmt.Sprintf(
					"Did you rename type %q to %q? ",
					oldName,
					newName,
				),
			)

			if err != nil {
				return nil, nil, err
			}

			if ok {
				renamedTypes[oldName] = newName
				break
			}
		}
	}

	typeDeltas := []*TypesDelta{}

	// Handle renamed types.
	for oldName, newName := range renamedTypes {
		typ1 := schema1.Get(oldName)
		typ2 := schema2.Get(newName)

		removed, added, _, deltas, err := DiffTypes(newName, typ1, typ2)

		if err != nil {
			return nil, nil, err
		}

		typeDeltas = append(
			typeDeltas,
			NewTypesDelta(newName, removed, added, deltas),
		)

		removedTypes = RemoveString(
			removedTypes,
			oldName,
		)

		addedTypes = RemoveType(addedTypes, newName)
	}

	// Handle types that have the same name.
	for _, name := range sameTypes {
		typ1 := schema1.Get(name)
		typ2 := schema2.Get(name)

		newTypeName := name

		if renamed, ok := renamedTypes[name]; ok {
			newTypeName = renamed
		}

		removed, added, _, deltas, err := DiffTypes(newTypeName, typ1, typ2)

		if err != nil {
			return nil, nil, err
		}

		typeDeltas = append(typeDeltas, NewTypesDelta(name, removed, added, deltas))
	}

	schemaDelta := NewSchemaDelta(removedTypes, addedTypes, renamedTypes)

	return schemaDelta, typeDeltas, nil
}
