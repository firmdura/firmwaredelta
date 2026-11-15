// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Value is a closed union for change evidence. Set at most one member. A zero
// Value means JSON null; constructors are convenient and do not retain slices
// or Entry pointers owned by the caller. String represents mode, target, class,
// endian or SONAME according to Change.Field. Machine is the ELF machine number.
// Needed points to a list so [] (an ELF with no dependencies) differs from null
// (no ELF). MarshalJSON emits the selected value directly.
type Value struct {
	Entry   *Entry
	Content *Content
	String  *string
	Machine *uint16
	Needed  *[]string
}

func NullValue() Value             { return Value{} }
func EntryValue(e Entry) Value     { e = cloneEntry(e); return Value{Entry: &e} }
func ContentValue(c Content) Value { return Value{Content: &c} }
func StringValue(s string) Value   { return Value{String: &s} }
func MachineValue(n uint16) Value  { return Value{Machine: &n} }
func NeededValue(names []string) Value {
	names = canonicalNames(names)
	return Value{Needed: &names}
}

func (v Value) member() (string, any, error) {
	n, name, data := 0, "null", any(nil)
	if v.Entry != nil {
		n++
		name, data = "entry", v.Entry
	}
	if v.Content != nil {
		n++
		name, data = "content", v.Content
	}
	if v.String != nil {
		n++
		name, data = "string", v.String
	}
	if v.Machine != nil {
		n++
		name, data = "machine", v.Machine
	}
	if v.Needed != nil {
		n++
		name, data = "needed", v.Needed
	}
	if n > 1 {
		return "", nil, errors.New("change value has multiple members")
	}
	return name, data, nil
}

func (v Value) IsNull() bool {
	return v.Entry == nil && v.Content == nil && v.String == nil && v.Machine == nil && v.Needed == nil
}

func (v Value) MarshalJSON() ([]byte, error) {
	_, data, err := v.member()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (v *Value) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var result Value
	if len(data) == 0 {
		return errors.New("empty change value")
	}
	switch data[0] {
	case 'n':
		if !bytes.Equal(data, []byte("null")) {
			return errors.New("invalid null value")
		}
	case '"':
		var s string
		if err := strictJSON(data, &s); err != nil {
			return err
		}
		result = StringValue(s)
	case '[':
		var names []string
		if err := strictJSON(data, &names); err != nil {
			return err
		}
		// Decoding preserves evidence order; normalization is explicit.
		result.Needed = &names
	case '{':
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			return err
		}
		if _, ok := keys["path"]; ok {
			var e Entry
			if err := strictJSON(data, &e); err != nil {
				return err
			}
			result.Entry = &e
		} else {
			var c struct {
				Size   *int64 `json:"size"`
				SHA256 string `json:"sha256"`
			}
			if err := strictJSON(data, &c); err != nil {
				return err
			}
			if c.Size == nil {
				return errors.New("content value requires size")
			}
			result = ContentValue(Content{Size: *c.Size, SHA256: c.SHA256})
		}
	default:
		var n uint16
		if err := strictJSON(data, &n); err != nil {
			return fmt.Errorf("invalid machine value: %w", err)
		}
		result = MachineValue(n)
	}
	*v = result
	return nil
}

func strictJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
