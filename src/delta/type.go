package delta

import (
	"fmt"

	"github.com/chuckyQ/pgdb/parser"
)

type TypeDelta struct {
	TypName  string
	PrevName string
	NewName  string
	PrevType string
	NewType  string
}

func NewTypeDelta(
	typName string,
	prevName string,
	newName string,
	prevType string,
	newType string,
) *TypeDelta {
	return &TypeDelta{
		TypName:  typName,
		PrevName: prevName,
		NewName:  newName,
		PrevType: prevType,
		NewType:  newType,
	}
}

func (t *TypeDelta) ToSQL() []string {
	queries := make([]string, 0)

	if t.PrevName != t.NewName {
		queries = append(
			queries,
			fmt.Sprintf(
				"ALTER TABLE %s RENAME COLUMN %s TO %s;",
				t.TypName,
				t.PrevName,
				t.NewName,
			),
		)
	}

	if t.PrevType != t.NewType {
		queries = append(
			queries,
			fmt.Sprintf(
				"ALTER TABLE %s ALTER COLUMN %s TYPE %s;",
				t.TypName,
				t.NewName,
				t.NewType,
			),
		)
	}

	return queries
}

func DiffTypes(typName string, typ1 *parser.Type, typ2 *parser.Type) (removed []string, added []*parser.Field, same []string, deltas []*TypeDelta, err error) {

	removed, added, same = typ1.Diff(typ2)

	renames := make(map[string]*parser.Field)
	usedNewNames := make(map[string]struct{})

	for _, oldName := range removed {
		if _, ok := renames[oldName]; ok {
			continue
		}

		for _, newField := range added {
			if _, ok := usedNewNames[newField.Name]; ok {
				continue
			}

			ok, err := GetYesNo(
				fmt.Sprintf(
					"Did you rename %q to %q in %q? ",
					oldName,
					newField.Name,
					typName,
				),
			)

			if err != nil {
				return nil, nil, nil, nil, err
			}

			if ok {
				renames[oldName] = newField
				usedNewNames[newField.Name] = struct{}{}
				break
			}
		}
	}

	// Fields that exist in both schemas.
	for _, name := range same {
		prevField := typ1.Get(name)
		newField := typ2.Get(name)

		_, typeChanged := prevField.Diff(newField)

		if typeChanged {
			deltas = append(deltas, NewTypeDelta(typName, name, name, prevField.Typ, newField.Typ))
		}
	}

	// Handle renamed fields.
	for oldName, newField := range renames {
		prevField := typ1.Get(oldName)
		newField2 := typ2.Get(newField.Name)

		deltas = append(
			deltas,
			NewTypeDelta(typName, oldName, newField.Name, prevField.Typ, newField2.Typ),
		)

		removed = RemoveString(
			removed,
			oldName,
		)

		added = RemoveField(
			added,
			newField,
		)
	}

	return removed, added, same, deltas, nil
}
