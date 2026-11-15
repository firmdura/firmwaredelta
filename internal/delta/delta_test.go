// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package delta_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/firmdura/firmwaredelta/internal/delta"
	"github.com/firmdura/firmwaredelta/internal/model"
)

func inventory(entries ...model.Entry) model.Inventory {
	return model.Inventory{SchemaVersion: model.SchemaVersion, Entries: entries}
}

func entry(path string, kind model.Kind) model.Entry {
	e := model.Entry{Path: path, Kind: kind, Mode: "0644", Category: model.CategoryOther}
	switch kind {
	case model.KindFile:
		size := int64(12)
		e.Size, e.SHA256 = &size, strings.Repeat("a", 64)
	case model.KindSymlink:
		target := "../literal/target"
		e.Target = &target
	}
	return e
}

func elf() *model.ELF {
	return &model.ELF{Class: "64", Endian: "little", Machine: 62, SONAME: "libsample.so.1", Needed: []string{"libc.so.6", "libz.so.1"}}
}

func compare(t *testing.T, before, after model.Inventory) model.Report {
	t.Helper()
	r, err := delta.Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("invalid output: %v", err)
	}
	if r.Counts != (model.Counts{Total: len(r.Changes), Unexpected: len(r.Changes)}) || len(r.PolicyWarnings) != 0 {
		t.Fatalf("delta applied policy decisions: %+v", r)
	}
	for _, c := range r.Changes {
		if c.Expected || c.Reason != "" {
			t.Fatalf("delta applied policy decision: %+v", c)
		}
	}
	return r
}

func valueJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fields(r model.Report) []model.Field {
	result := make([]model.Field, len(r.Changes))
	for i, c := range r.Changes {
		result[i] = c.Field
	}
	return result
}

func TestEmptyAndIdentical(t *testing.T) {
	for _, inv := range []model.Inventory{inventory(), inventory(entry("empty-dir", model.KindDirectory), entry("file", model.KindFile))} {
		r := compare(t, inv, inv)
		if len(r.Changes) != 0 || r.Verdict != model.VerdictUnchanged || r.BaselineDigest != r.CandidateDigest {
			t.Fatalf("identical inputs: %+v", r)
		}
		if r.Changes == nil || r.PolicyWarnings == nil {
			t.Fatal("canonical empty lists must be non-nil")
		}
	}
	r := compare(t, inventory(), inventory())
	sum := sha256.Sum256([]byte(`{"schema_version":1,"entries":[]}`))
	if r.BaselineDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("empty canonical digest = %s", r.BaselineDigest)
	}
}

var kinds = []model.Kind{model.KindFile, model.KindDirectory, model.KindSymlink, model.KindBlockDevice, model.KindCharDevice, model.KindFIFO, model.KindSocket}

func TestPresenceAndAllKindTransitions(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			e := entry("path", kind)
			e.Category = model.CategoryConfig
			if kind == model.KindFile {
				e.ELF = elf()
			}
			for _, added := range []bool{true, false} {
				before, after := inventory(), inventory(e)
				if !added {
					before, after = after, before
				}
				r := compare(t, before, after)
				if !slices.Equal(fields(r), []model.Field{model.FieldPresence}) || r.Verdict != model.VerdictUnexpectedChanges {
					t.Fatalf("presence: %+v", r)
				}
				c := r.Changes[0]
				if c.Category != e.Category || c.Path != e.Path || c.Before.IsNull() != added || c.After.IsNull() == added {
					t.Fatalf("wrong presence direction/category: %+v", c)
				}
				present := c.After
				if !added {
					present = c.Before
				}
				if valueJSON(t, present) != valueJSON(t, e) {
					t.Fatalf("lost full presence entry: %+v", present)
				}
			}
		})
	}
	for _, beforeKind := range kinds {
		for _, afterKind := range kinds {
			if beforeKind == afterKind {
				continue
			}
			t.Run(string(beforeKind)+"_to_"+string(afterKind), func(t *testing.T) {
				b, a := entry("path", beforeKind), entry("path", afterKind)
				b.Category, a.Category, a.Mode = model.CategoryLibrary, model.CategoryConfig, "4755"
				r := compare(t, inventory(b), inventory(a))
				if !slices.Equal(fields(r), []model.Field{model.FieldKind}) {
					t.Fatalf("kind must be the only record: %+v", r)
				}
				c := r.Changes[0]
				if c.Category != a.Category || valueJSON(t, c.Before) != valueJSON(t, b) || valueJSON(t, c.After) != valueJSON(t, a) {
					t.Fatalf("lost full kind evidence: %+v", c)
				}
			})
		}
	}
}

func TestSameKindAtomicFields(t *testing.T) {
	cases := []struct {
		name  string
		kind  model.Kind
		field model.Field
		edit  func(*model.Entry)
		want  model.Value
	}{
		{"mode", model.KindFile, model.FieldMode, func(e *model.Entry) { e.Mode = "4755" }, model.StringValue("4755")},
		{"hash", model.KindFile, model.FieldContent, func(e *model.Entry) { e.SHA256 = strings.Repeat("b", 64) }, model.ContentValue(model.Content{Size: 12, SHA256: strings.Repeat("b", 64)})},
		{"size", model.KindFile, model.FieldContent, func(e *model.Entry) { n := int64(13); e.Size = &n }, model.ContentValue(model.Content{Size: 13, SHA256: strings.Repeat("a", 64)})},
		{"target", model.KindSymlink, model.FieldTarget, func(e *model.Entry) { target := "/outside/literal"; e.Target = &target }, model.StringValue("/outside/literal")},
		{"class", model.KindFile, model.FieldELFClass, func(e *model.Entry) { e.ELF.Class = "32" }, model.StringValue("32")},
		{"endian", model.KindFile, model.FieldELFEndian, func(e *model.Entry) { e.ELF.Endian = "big" }, model.StringValue("big")},
		{"machine", model.KindFile, model.FieldELFMachine, func(e *model.Entry) { e.ELF.Machine = 0 }, model.MachineValue(0)},
		{"soname", model.KindFile, model.FieldELFSONAME, func(e *model.Entry) { e.ELF.SONAME = "" }, model.StringValue("")},
		{"needed", model.KindFile, model.FieldELFNeeded, func(e *model.Entry) { e.ELF.Needed = nil }, model.NeededValue(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, a := entry("path", tc.kind), entry("path", tc.kind)
			if tc.kind == model.KindFile {
				b.ELF, a.ELF = elf(), elf()
			}
			tc.edit(&a)
			a.Category = model.CategoryConfig
			r := compare(t, inventory(b), inventory(a))
			if !slices.Equal(fields(r), []model.Field{tc.field}) || r.Changes[0].Category != a.Category {
				t.Fatalf("wrong atomic changes: %+v", r)
			}
			if valueJSON(t, r.Changes[0].After) != valueJSON(t, tc.want) {
				t.Fatalf("wrong value: %s", valueJSON(t, r.Changes[0].After))
			}
			reverse := compare(t, inventory(a), inventory(b))
			if valueJSON(t, reverse.Changes[0].Before) != valueJSON(t, r.Changes[0].After) || valueJSON(t, reverse.Changes[0].After) != valueJSON(t, r.Changes[0].Before) {
				t.Fatal("reverse comparison lost before/after evidence")
			}
		})
	}
	for _, kind := range kinds {
		b, a := entry("path", kind), entry("path", kind)
		a.Mode = "7777"
		if r := compare(t, inventory(b), inventory(a)); !slices.Equal(fields(r), []model.Field{model.FieldMode}) {
			t.Fatalf("mode lost for kind %s: %+v", kind, r)
		}
	}
}

func TestAllFileFieldsTogether(t *testing.T) {
	b, a := entry("lib/tool", model.KindFile), entry("lib/tool", model.KindFile)
	b.ELF, a.ELF = elf(), &model.ELF{Class: "32", Endian: "big", Machine: 40, SONAME: "libsample.so.2", Needed: []string{"libnew.so", "libnew.so"}}
	a.Mode, a.SHA256 = "4755", strings.Repeat("b", 64)
	*a.Size = 24
	r := compare(t, inventory(b), inventory(a))
	want := []model.Field{model.FieldContent, model.FieldELFClass, model.FieldELFEndian, model.FieldELFMachine, model.FieldELFNeeded, model.FieldELFSONAME, model.FieldMode}
	if !slices.Equal(fields(r), want) {
		t.Fatalf("lost simultaneous change: got %v, want %v", fields(r), want)
	}
	if got := valueJSON(t, r.Changes[4].After); got != `["libnew.so"]` {
		t.Fatalf("noncanonical needed value: %s", got)
	}
}

func TestELFAppearsAndDisappears(t *testing.T) {
	for _, added := range []bool{true, false} {
		b, a := entry("path", model.KindFile), entry("path", model.KindFile)
		// Empty metadata values must remain distinct from the non-ELF null side.
		a.ELF = &model.ELF{Class: "64", Endian: "little", Machine: 0, SONAME: "", Needed: nil}
		a.SHA256 = strings.Repeat("b", 64)
		if !added {
			b, a = a, b
		}
		r := compare(t, inventory(b), inventory(a))
		want := []model.Field{model.FieldContent, model.FieldELFClass, model.FieldELFEndian, model.FieldELFMachine, model.FieldELFNeeded, model.FieldELFSONAME}
		if !slices.Equal(fields(r), want) {
			t.Fatalf("ELF transition lost fields: %v", fields(r))
		}
		for _, c := range r.Changes[1:] {
			if c.Before.IsNull() != added || c.After.IsNull() == added {
				t.Fatalf("ELF transition lost null: %+v", c)
			}
		}
	}
}

func TestOrderingCanonicalDigestsAndOwnership(t *testing.T) {
	b, a := entry("z", model.KindFile), entry("z", model.KindFile)
	b.ELF, a.ELF = elf(), elf()
	b.ELF.Needed = []string{"libz.so.1", "libc.so.6", "libz.so.1"}
	a.ELF.Needed = []string{"libc.so.6", "libz.so.1"}
	a.Category = model.CategoryExecutable // Category alone is not a compared field.
	base := inventory(b, entry("a", model.KindDirectory))
	candidate := inventory(entry("a", model.KindDirectory), a)
	beforeBase, beforeCandidate := valueJSON(t, base), valueJSON(t, candidate)
	r := compare(t, base, candidate)
	if len(r.Changes) != 0 {
		t.Fatalf("equivalent needed sets/category-only change: %+v", r)
	}
	if valueJSON(t, base) != beforeBase || valueJSON(t, candidate) != beforeCandidate {
		t.Fatal("comparison mutated inventories while canonicalizing")
	}
	// Digest includes category even though category alone has no atomic record.
	if r.BaselineDigest == r.CandidateDigest {
		t.Fatal("digest omitted inventory category")
	}
	for _, pair := range []struct {
		inv    model.Inventory
		digest string
	}{{base, r.BaselineDigest}, {candidate, r.CandidateDigest}} {
		raw, err := model.CanonicalInventoryJSON(pair.inv)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if pair.digest != hex.EncodeToString(sum[:]) {
			t.Fatal("report digest differs from SHA-256 of canonical inventory bytes")
		}
	}
	// Verify full-entry and nested metadata in presence results do not alias input.
	added := compare(t, inventory(), base)
	*added.Changes[1].After.Entry.Size = 999
	added.Changes[1].After.Entry.ELF.Needed[0] = "mutated"
	if valueJSON(t, base) != beforeBase {
		t.Fatal("report aliases input entry metadata")
	}
	// Canonical same-kind needed arrays also have independent ownership.
	a.ELF.Needed = []string{"libdifferent.so"}
	changed := compare(t, inventory(b), inventory(a))
	(*changed.Changes[0].Before.Needed)[0] = "mutated"
	if b.ELF.Needed[0] != "libz.so.1" {
		t.Fatal("atomic report values alias input ELF metadata")
	}
}

func TestInputPermutationProducesIdenticalBytes(t *testing.T) {
	base := []model.Entry{entry("z", model.KindFile), entry("a", model.KindSymlink), entry("middle", model.KindDirectory)}
	candidate := []model.Entry{entry("new", model.KindDirectory), entry("z", model.KindFile), entry("a", model.KindSymlink)}
	candidate[1].Mode = "0755"
	candidate[1].SHA256 = strings.Repeat("b", 64)
	target := "replacement"
	candidate[2].Target = &target
	want := valueJSON(t, compare(t, inventory(base...), inventory(candidate...)))
	for _, bp := range permutations(base) {
		for _, ap := range permutations(candidate) {
			if got := valueJSON(t, compare(t, inventory(bp...), inventory(ap...))); got != want {
				t.Fatalf("permuted inputs changed report:\n%s\n%s", got, want)
			}
		}
	}
}

func permutations(entries []model.Entry) [][]model.Entry {
	if len(entries) == 0 {
		return [][]model.Entry{{}}
	}
	var result [][]model.Entry
	for i, e := range entries {
		rest := slices.Delete(slices.Clone(entries), i, i+1)
		for _, p := range permutations(rest) {
			result = append(result, append([]model.Entry{e}, p...))
		}
	}
	return result
}

func TestRejectInvalidInventoriesWithoutPartialReport(t *testing.T) {
	valid := inventory(entry("path", model.KindFile))
	invalid := []model.Inventory{
		{},
		{SchemaVersion: 2},
		inventory(entry("../escape", model.KindFile)),
		inventory(entry("path", model.KindFile), entry("path", model.KindFile)),
		inventory(model.Entry{Path: "path", Kind: model.KindFile, Mode: "0644", Category: model.CategoryOther}),
	}
	for _, bad := range invalid {
		for _, candidateBad := range []bool{true, false} {
			b, a := bad, valid
			if candidateBad {
				b, a = a, b
			}
			r, err := delta.Compare(b, a)
			var typed *model.InputError
			if !errors.As(err, &typed) || !reflect.DeepEqual(r, model.Report{}) {
				t.Fatalf("invalid input produced partial report or lost error type: %+v, %v", r, err)
			}
		}
	}
}

func ExampleCompare() {
	read := func(name string) model.Inventory {
		data, err := os.ReadFile("../../testdata/delta/" + name + ".json")
		if err != nil {
			panic(err)
		}
		var inv model.Inventory
		if err := json.Unmarshal(data, &inv); err != nil {
			panic(err)
		}
		return inv
	}
	r, err := delta.Compare(read("baseline"), read("candidate"))
	if err != nil {
		panic(err)
	}
	for _, c := range r.Changes {
		fmt.Printf("%s %s expected=%t\n", c.Path, c.Field, c.Expected)
	}
	fmt.Println(r.Verdict)
	// Output:
	// etc/tool.conf content expected=false
	// usr/bin/tool content expected=false
	// unexpected_changes
}
