package main

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const tagName = "pgql"

// UnmarshalStrings unmarshals rows of string values into either:
//
//   - *Struct
//   - *[]Struct
//   - []*Struct
//
// Struct fields can specify the source column using:
//
//	type User struct {
//	    ID       string `pgql:"id"`
//	    Username string `pgql:"username"`
//	    Password string `pgql:"password"`
//	}
//
// If no pgql tag is present, the Go field name is used.
func UnmarshalStrings(columns []string, nulls [][]bool, values [][]string, dst any) error {
	if dst == nil {
		return fmt.Errorf("destination cannot be nil")
	}

	rv := reflect.ValueOf(dst)

	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf(
			"destination must be a non-nil pointer to a struct or slice",
		)
	}

	elem := rv.Elem()

	switch elem.Kind() {

	case reflect.Struct:
		// Unmarshal the first row into a single struct.
		if len(values) == 0 {
			return nil
		}

		if err := unmarshalStruct(columns, values[0], nulls[0], elem); err != nil {
			return err
		}

		return nil

	case reflect.Slice:
		return unmarshalSlice(columns, nulls, values, elem)

	default:
		return fmt.Errorf(
			"destination must be a pointer to a struct or slice of structs",
		)
	}
}

func unmarshalSlice(
	fields []string,
	nulls [][]bool,
	values [][]string,
	dst reflect.Value,
) error {
	elemType := dst.Type().Elem()

	// *[]Struct
	if elemType.Kind() == reflect.Struct {
		result := reflect.MakeSlice(
			dst.Type(),
			len(values),
			len(values),
		)

		for i, row := range values {
			if err := unmarshalStruct(
				fields,
				row,
				nulls[i],
				result.Index(i),
			); err != nil {
				return fmt.Errorf("row %d: %w", i, err)
			}
		}

		dst.Set(result)
		return nil
	}

	// *[]*Struct
	if elemType.Kind() == reflect.Pointer &&
		elemType.Elem().Kind() == reflect.Struct {

		result := reflect.MakeSlice(
			dst.Type(),
			len(values),
			len(values),
		)

		for i, row := range values {
			structValue := reflect.New(elemType.Elem())

			if err := unmarshalStruct(
				fields,
				row,
				nulls[i],
				structValue.Elem(),
			); err != nil {
				return fmt.Errorf("row %d: %w", i, err)
			}

			result.Index(i).Set(structValue)
		}

		dst.Set(result)
		return nil
	}

	return fmt.Errorf(
		"destination must be a slice of structs or pointers to structs",
	)
}

func unmarshalStruct(
	fields []string,
	values []string,
	nulls []bool,
	dst reflect.Value,
) error {
	if dst.Kind() != reflect.Struct {
		return fmt.Errorf("destination must be a struct")
	}

	if len(values) < len(fields) {
		return fmt.Errorf(
			"not enough values: got %d, expected %d",
			len(values),
			len(fields),
		)
	}

	// Build a map from pgql tag -> struct field.
	fieldMap := make(map[string]reflect.Value)

	t := dst.Type()

	for i := 0; i < t.NumField(); i++ {
		structField := t.Field(i)

		// Ignore unexported fields.
		if structField.PkgPath != "" {
			continue
		}

		tag := structField.Tag.Get(tagName)

		// No tag means use the Go field name.
		if tag == "" {
			tag = structField.Name
		}

		// Support:
		//
		// pgql:"-"
		//
		// to explicitly ignore a field.
		if tag == "-" {
			continue
		}

		// Support options such as:
		//
		// pgql:"username,omitempty"
		//
		tag = strings.Split(tag, ",")[0]

		fieldMap[tag] = dst.Field(i)
	}

	for i, columnName := range fields {
		field, ok := fieldMap[columnName]

		if !ok {
			// No matching struct field.
			continue
		}

		if !field.CanSet() {
			continue
		}

		if err := setStringValue(field, nulls[i], values[i]); err != nil {
			return fmt.Errorf(
				"field %q: %w",
				columnName,
				err,
			)
		}
	}

	return nil
}

func setStringValue(
	field reflect.Value,
	null bool,
	value string,
) error {

	if field.Kind() == reflect.Pointer && null {
		field.Set(reflect.Zero(field.Type()))
		return nil
	}

	switch field.Kind() {

	case reflect.Pointer:

		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}

		return setStringValue(field.Elem(), false, value)

	case reflect.String:
		field.SetString(value)

	case reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:

		n, err := strconv.ParseInt(
			value,
			10,
			field.Type().Bits(),
		)

		if err != nil {
			return fmt.Errorf(
				"invalid integer %q: %w",
				value,
				err,
			)
		}

		field.SetInt(n)

	case reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:

		n, err := strconv.ParseUint(
			value,
			10,
			field.Type().Bits(),
		)

		if err != nil {
			return fmt.Errorf(
				"invalid unsigned integer %q: %w",
				value,
				err,
			)
		}

		field.SetUint(n)

	case reflect.Bool:
		b, err := strconv.ParseBool(value)

		if err != nil {
			return fmt.Errorf(
				"invalid bool %q: %w",
				value,
				err,
			)
		}

		field.SetBool(b)

	case reflect.Float32,
		reflect.Float64:

		n, err := strconv.ParseFloat(
			value,
			field.Type().Bits(),
		)

		if err != nil {
			return fmt.Errorf(
				"invalid float %q: %w",
				value,
				err,
			)
		}

		field.SetFloat(n)

	default:
		return fmt.Errorf(
			"unsupported field type %s",
			field.Type(),
		)
	}

	return nil
}
