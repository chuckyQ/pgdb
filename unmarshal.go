package main

import (
	"fmt"
	"reflect"
	"strconv"
)

func UnmarshalStrings(values [][]string, dst any) error {
	rv := reflect.ValueOf(dst)

	elem := rv.Elem()

	switch elem.Kind() {
	case reflect.Struct:
		// Single struct.
		if len(values) != 1 {
			return fmt.Errorf(
				"expected 1 row for struct, got %d",
				len(values),
			)
		}

		return unmarshalStruct(values[0], elem)

	case reflect.Slice:
		// Slice of structs.
		structType := elem.Type().Elem()

		if structType.Kind() != reflect.Struct {
			fmt.Println(structType.Kind())
			return fmt.Errorf(
				"destination must be a pointer to a struct or slice of structs",
			)
		}

		result := reflect.MakeSlice(
			elem.Type(),
			len(values),
			len(values),
		)

		for i, row := range values {
			if err := unmarshalStruct(row, result.Index(i)); err != nil {
				return fmt.Errorf("row %d: %w", i, err)
			}
		}

		elem.Set(result)

		return nil

	default:
		return fmt.Errorf(
			"destination must be a pointer to a struct or slice of structs",
		)
	}
}

func unmarshalStruct(values []string, dst reflect.Value) error {
	if dst.Kind() != reflect.Struct {
		return fmt.Errorf("destination must be a struct")
	}

	if len(values) != dst.NumField() {
		return fmt.Errorf(
			"expected %d values, got %d",
			dst.NumField(),
			len(values),
		)
	}

	for i, value := range values {
		field := dst.Field(i)

		if !field.CanSet() {
			continue
		}

		if err := setStringValue(field, value); err != nil {
			return fmt.Errorf(
				"field %d: %w",
				i,
				err,
			)
		}
	}

	return nil
}

func setStringValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
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

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
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

	case reflect.Float32, reflect.Float64:
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
