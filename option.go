package ident

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type Option[T any] struct {
	// Value is the value of the option.
	Value T
	// Valid is true if the value is set.
	Valid bool
}

// NewOption returns a new valid Option with the given value.
func NewOption[T any](value T) Option[T] {
	return Option[T]{Value: value, Valid: true}
}

func (o Option[T]) MarshalJSON() ([]byte, error) {
	if !o.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(o.Value)
}

func (o *Option[T]) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &o.Value); err != nil {
		return err
	}
	o.Valid = true
	return nil
}

func (o Option[T]) String() string {
	if !o.Valid {
		return "empty"
	}
	return fmt.Sprintf("%v", o.Value)
}

func (o *Option[T]) Set(i interface{}) {
	if i == nil {
		o.Valid = false
	} else {
		o.Value = i.(T)
	}
}

func (o Option[T]) Get() interface{} {
	if !o.Valid {
		return nil
	}
	return o.Value
}

func MarshalJSONOptionStruct(s interface{}) ([]byte, error) {
	type Getter interface {
		Get() interface{}
	}
	m := make(map[string]interface{})
	v := reflect.ValueOf(s)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name, omitEmpty := parseJsonTag(t.Field(i))
		if name != "" {
			f := v.Field(i).Interface()
			if g, ok := f.(Getter); ok {
				f = g.Get()
			}
			if omitEmpty {
				if f == nil || reflect.ValueOf(f).IsZero() {
					continue
				}
			}
			m[name] = f
		}
	}
	return json.Marshal(m)
}

func parseJsonTag(f reflect.StructField) (name string, omitEmpty bool) {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name, false
	}
	i := strings.IndexByte(tag, ',')
	if i != -1 {
		omitEmpty = tag[i+1:] == "omitempty"
		name = tag[:i]
	} else {
		name = tag
	}
	if name == "-" {
		return "", omitEmpty
	}
	if name == "" {
		name = f.Name
	}
	return name, omitEmpty
}
