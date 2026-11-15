// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firmdura/firmwaredelta/internal/model"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "model", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContractExamples(t *testing.T) {
	for _, family := range []string{"inventory", "policy", "report"} {
		for _, example := range []string{"empty", "normal", "invalid"} {
			t.Run(family+"/"+example, func(t *testing.T) {
				var v interface{ Validate() error }
				switch family {
				case "inventory":
					v = new(model.Inventory)
				case "policy":
					v = new(model.Policy)
				case "report":
					v = new(model.Report)
				}
				if err := json.Unmarshal(fixture(t, family+"-"+example+".json"), v); err != nil {
					t.Fatal(err)
				}
				err := v.Validate()
				if (err != nil) != (example == "invalid") {
					t.Fatalf("Validate() = %v", err)
				}
			})
		}
	}
}

func TestContractSchemas(t *testing.T) {
	for _, family := range []string{"inventory", "policy", "report"} {
		t.Run(family, func(t *testing.T) {
			path := filepath.Join("..", "..", "schemas", family+"-v1.json")
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := jsonschema.UnmarshalJSON(f)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			compiler := jsonschema.NewCompiler()
			location := "https://firmwaredelta.invalid/schemas/" + family + "-v1.json"
			if err := compiler.AddResource(location, doc); err != nil {
				t.Fatal(err)
			}
			schema, err := compiler.Compile(location)
			if err != nil {
				t.Fatal(err)
			}
			for _, example := range []string{"empty", "normal", "invalid"} {
				value, err := jsonschema.UnmarshalJSON(bytes.NewReader(fixture(t, family+"-"+example+".json")))
				if err != nil {
					t.Fatal(err)
				}
				err = schema.Validate(value)
				if (err != nil) != (example == "invalid") {
					t.Fatalf("%s schema result: %v", example, err)
				}
			}
		})
	}
}

func TestContractCanonicalInventory(t *testing.T) {
	var i model.Inventory
	if err := json.Unmarshal(fixture(t, "inventory-normal.json"), &i); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(i)
	want, err := model.CanonicalInventoryJSON(i)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := model.InventoryDigest(i)
	if err != nil {
		t.Fatal(err)
	}
	permuted := model.Inventory{SchemaVersion: 1, Entries: append([]model.Entry{}, i.Entries...)}
	for l, r := 0, len(permuted.Entries)-1; l < r; l, r = l+1, r-1 {
		permuted.Entries[l], permuted.Entries[r] = permuted.Entries[r], permuted.Entries[l]
	}
	// DT_NEEDED is a set in the canonical contract, not evidence order.
	for n := range permuted.Entries {
		if permuted.Entries[n].ELF != nil {
			e := *permuted.Entries[n].ELF
			e.Needed = []string{"libc.so.6", "libc.so.6"}
			permuted.Entries[n].ELF = &e
		}
	}
	got, err := model.CanonicalInventoryJSON(permuted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("permutation changed canonical bytes\n%s\n%s", want, got)
	}
	gotDigest, _ := model.InventoryDigest(permuted)
	if digest != gotDigest {
		t.Fatal("permutation changed digest")
	}
	after, _ := json.Marshal(i)
	if !bytes.Equal(before, after) {
		t.Fatal("canonicalization mutated caller input")
	}
	empty := model.Inventory{SchemaVersion: 1}
	b, _ := model.CanonicalInventoryJSON(empty)
	if string(b) != `{"schema_version":1,"entries":[]}` {
		t.Fatalf("empty inventory bytes: %s", b)
	}
	d, _ := model.InventoryDigest(empty)
	if d != "ba4fc47c6525d8de1a187fe7d41e1de1b2fe52df1f6a43d0544675d3ac44e5fe" {
		t.Fatalf("empty inventory digest changed: %s", d)
	}
}

func TestContractInvalidEntriesAndPaths(t *testing.T) {
	for _, path := range []string{"", ".", "/root", "a/..", "a/./b", "a//b", "a/", "a\x00b", string([]byte{0xff}), strings.Repeat("a", 4097)} {
		if model.ValidatePath(path) == nil {
			t.Errorf("accepted invalid path %q", path)
		}
	}
	for _, path := range []string{"etc/a", "literal\\name", "a/*", "pipe|`\n<name>", strings.Repeat("a", 4096)} {
		if err := model.ValidatePath(path); err != nil {
			t.Errorf("valid literal path %q: %v", path, err)
		}
	}
	size := int64(0)
	base := model.Entry{Path: "a", Kind: model.KindFile, Mode: "0644", Category: model.CategoryOther, Size: &size, SHA256: strings.Repeat("a", 64)}
	cases := []struct {
		name string
		edit func(*model.Entry)
	}{
		{"unknown kind", func(e *model.Entry) { e.Kind = "unknown" }},
		{"unknown category", func(e *model.Entry) { e.Category = "safe" }},
		{"mode", func(e *model.Entry) { e.Mode = "644" }},
		{"size missing", func(e *model.Entry) { e.Size = nil }},
		{"hash", func(e *model.Entry) { e.SHA256 = "content" }},
		{"non-file content", func(e *model.Entry) { e.Kind = model.KindDirectory }},
		{"ELF class", func(e *model.Entry) { e.ELF = &model.ELF{Class: "128", Endian: "little"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.edit(&e)
			if e.Validate() == nil {
				t.Fatal("invalid entry accepted")
			}
		})
	}
	if err := (model.Inventory{SchemaVersion: 1, Entries: []model.Entry{base, base}}).Validate(); err == nil {
		t.Fatal("duplicate inventory path accepted")
	}
	if err := (model.Inventory{SchemaVersion: 2}).Validate(); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestContractChangeValues(t *testing.T) {
	values := []struct {
		field         model.Field
		before, after model.Value
	}{
		{model.FieldContent, model.ContentValue(model.Content{Size: 1, SHA256: strings.Repeat("a", 64)}), model.ContentValue(model.Content{Size: 2, SHA256: strings.Repeat("b", 64)})},
		{model.FieldMode, model.StringValue("0644"), model.StringValue("0755")},
		{model.FieldTarget, model.StringValue("old"), model.StringValue("new")},
		{model.FieldELFClass, model.NullValue(), model.StringValue("64")},
		{model.FieldELFEndian, model.StringValue("big"), model.StringValue("little")},
		{model.FieldELFMachine, model.NullValue(), model.MachineValue(62)},
		{model.FieldELFSONAME, model.NullValue(), model.StringValue("")},
		{model.FieldELFNeeded, model.NullValue(), model.NeededValue(nil)},
	}
	for _, tc := range values {
		t.Run(string(tc.field), func(t *testing.T) {
			c := model.Change{Path: "a", Category: model.CategoryOther, Field: tc.field, Before: tc.before, After: tc.after}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var round model.Change
			if err := json.Unmarshal(b, &round); err != nil {
				t.Fatal(err)
			}
			if err := round.Validate(); err != nil {
				t.Fatal(err)
			}
			again, _ := json.Marshal(round)
			if !bytes.Equal(b, again) {
				t.Fatalf("round trip differs: %s / %s", b, again)
			}
		})
	}
	wrong := model.Change{Path: "a", Category: model.CategoryOther, Field: model.FieldMode, Before: model.StringValue("0644"), After: model.MachineValue(755)}
	if wrong.Validate() == nil {
		t.Fatal("wrong atomic shape accepted")
	}
	wrong.After = model.StringValue("0644")
	if wrong.Validate() == nil {
		t.Fatal("non-change accepted")
	}
	wrong.After = model.StringValue("0755")
	wrong.Expected = true
	if wrong.Validate() == nil {
		t.Fatal("expected change without rationale accepted")
	}
	if _, err := json.Marshal(model.Value{String: new(string), Machine: new(uint16)}); err == nil {
		t.Fatal("multiple value members accepted")
	}
}

func TestContractPresenceKindAndPolicy(t *testing.T) {
	size := int64(0)
	file := model.Entry{Path: "a", Kind: model.KindFile, Mode: "0644", Category: model.CategoryOther, Size: &size, SHA256: strings.Repeat("a", 64)}
	dir := model.Entry{Path: "a", Kind: model.KindDirectory, Mode: "0755", Category: model.CategoryOther}
	for _, c := range []model.Change{
		{Path: "a", Category: model.CategoryOther, Field: model.FieldPresence, Before: model.NullValue(), After: model.EntryValue(file)},
		{Path: "a", Category: model.CategoryOther, Field: model.FieldPresence, Before: model.EntryValue(file), After: model.NullValue()},
		{Path: "a", Category: model.CategoryOther, Field: model.FieldKind, Before: model.EntryValue(file), After: model.EntryValue(dir)},
	} {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var round model.Change
		if err := json.Unmarshal(b, &round); err != nil {
			t.Fatal(err)
		}
		if err := round.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	var unknown model.Value
	if err := json.Unmarshal([]byte(`{"size":0,"sha256":"`+strings.Repeat("a", 64)+`","contents":"private"}`), &unknown); err == nil {
		t.Fatal("unknown evidence field accepted")
	}
	for _, p := range []model.Policy{
		{SchemaVersion: 2},
		{SchemaVersion: 1, Allow: []model.Rule{{Path: "a", Fields: []model.Field{"unknown"}, Reason: "approved"}}},
		{SchemaVersion: 1, Allow: []model.Rule{{Path: "a", Fields: []model.Field{model.FieldMode}, Reason: "\u00a0"}}},
		{SchemaVersion: 1, Allow: []model.Rule{{Path: "a", Fields: []model.Field{model.FieldMode, model.FieldMode}, Reason: "approved"}}},
	} {
		if p.Validate() == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestContractReportDecisionsAndIsolation(t *testing.T) {
	var r model.Report
	if err := json.Unmarshal(fixture(t, "report-normal.json"), &r); err != nil {
		t.Fatal(err)
	}
	r.Changes[0], r.Changes[1] = r.Changes[1], r.Changes[0]
	n, err := model.NormalizeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	if n.Changes[0].Path != "etc/service.conf" {
		t.Fatal("report not path sorted")
	}
	n.Changes[0].Before.Content.Size = 999
	if r.Changes[1].Before.Content.Size == 999 {
		t.Fatal("normalized report aliases input")
	}
	r.Counts.Unexpected = 0
	if r.Validate() == nil {
		t.Fatal("inconsistent counts accepted")
	}
	r.Counts.Unexpected = 1
	r.Verdict = model.VerdictExpectedChanges
	if r.Validate() == nil {
		t.Fatal("strengthened verdict accepted")
	}
}

func TestContractTypedErrors(t *testing.T) {
	for _, err := range []error{&model.InputError{Op: "root", Err: context.Canceled}, &model.ScanError{Op: "read", Path: "etc/a", Err: context.Canceled}, &model.PolicyError{Op: "read", Err: context.Canceled}} {
		if !errors.Is(fmt.Errorf("outer: %w", err), context.Canceled) {
			t.Fatal("cause lost")
		}
	}
	var scan *model.ScanError
	if !errors.As(fmt.Errorf("outer: %w", &model.ScanError{Op: "read", Err: model.ErrInputChanged}), &scan) {
		t.Fatal("typed scan error lost")
	}
}
