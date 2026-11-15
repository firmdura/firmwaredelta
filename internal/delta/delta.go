// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package delta compares validated inventories without filesystem access or
// policy decisions. Added and removed paths produce one presence record;
// replacements produce one kind record containing both full entries. Same-kind
// entries produce every changed atomic field: content (size and hash together),
// mode, symlink target and the five ELF metadata fields. For example, rebuilding
// usr/bin/tool while editing etc/tool.conf produces separate content records;
// neither change is considered expected until a policy is applied elsewhere.
package delta

import (
	"slices"

	"github.com/firmdura/firmwaredelta/internal/model"
)

// Compare returns a canonical report of observed differences. It validates both
// inventories, computes their canonical digests and leaves all changes
// unexpected. Inputs and their nested metadata remain owned by the caller; the
// returned report does not alias them. Invalid inventories return an InputError
// and no partial report.
func Compare(baseline, candidate model.Inventory) (model.Report, error) {
	before, err := model.NormalizeInventory(baseline)
	if err != nil {
		return model.Report{}, &model.InputError{Op: "baseline inventory", Err: err}
	}
	after, err := model.NormalizeInventory(candidate)
	if err != nil {
		return model.Report{}, &model.InputError{Op: "candidate inventory", Err: err}
	}
	baselineDigest, err := model.InventoryDigest(before)
	if err != nil {
		return model.Report{}, err
	}
	candidateDigest, err := model.InventoryDigest(after)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		SchemaVersion:   model.SchemaVersion,
		BaselineDigest:  baselineDigest,
		CandidateDigest: candidateDigest,
		Changes:         []model.Change{},
		PolicyWarnings:  []model.Warning{},
		Verdict:         model.VerdictUnchanged,
	}
	appendChange := func(path string, category model.Category, field model.Field, b, a model.Value) {
		report.Changes = append(report.Changes, model.Change{
			Path: path, Category: category, Field: field, Before: b, After: a,
		})
	}
	for b, a := 0, 0; b < len(before.Entries) || a < len(after.Entries); {
		switch {
		case a == len(after.Entries) || b < len(before.Entries) && before.Entries[b].Path < after.Entries[a].Path:
			e := before.Entries[b]
			appendChange(e.Path, e.Category, model.FieldPresence, model.EntryValue(e), model.NullValue())
			b++
		case b == len(before.Entries) || after.Entries[a].Path < before.Entries[b].Path:
			e := after.Entries[a]
			appendChange(e.Path, e.Category, model.FieldPresence, model.NullValue(), model.EntryValue(e))
			a++
		default:
			old, next := before.Entries[b], after.Entries[a]
			if old.Kind != next.Kind {
				appendChange(next.Path, next.Category, model.FieldKind, model.EntryValue(old), model.EntryValue(next))
			} else {
				compareEntry(old, next, func(field model.Field, bv, av model.Value) {
					appendChange(next.Path, next.Category, field, bv, av)
				})
			}
			b++
			a++
		}
	}
	report.Counts = model.Counts{Total: len(report.Changes), Unexpected: len(report.Changes)}
	if report.Counts.Total != 0 {
		report.Verdict = model.VerdictUnexpectedChanges
	}
	return model.NormalizeReport(report)
}

func compareEntry(before, after model.Entry, emit func(model.Field, model.Value, model.Value)) {
	if before.Mode != after.Mode {
		emit(model.FieldMode, model.StringValue(before.Mode), model.StringValue(after.Mode))
	}
	switch before.Kind {
	case model.KindFile:
		if *before.Size != *after.Size || before.SHA256 != after.SHA256 {
			emit(model.FieldContent,
				model.ContentValue(model.Content{Size: *before.Size, SHA256: before.SHA256}),
				model.ContentValue(model.Content{Size: *after.Size, SHA256: after.SHA256}))
		}
		compareELF(before.ELF, after.ELF, emit)
	case model.KindSymlink:
		if *before.Target != *after.Target {
			emit(model.FieldTarget, model.StringValue(*before.Target), model.StringValue(*after.Target))
		}
	}
}

func compareELF(before, after *model.ELF, emit func(model.Field, model.Value, model.Value)) {
	if before == nil && after == nil {
		return
	}
	var b, a model.ELF
	if before != nil {
		b = *before
	}
	if after != nil {
		a = *after
	}
	absentSide := before == nil || after == nil
	stringValue := func(e *model.ELF, s string) model.Value {
		if e == nil {
			return model.NullValue()
		}
		return model.StringValue(s)
	}
	if absentSide || b.Class != a.Class {
		emit(model.FieldELFClass, stringValue(before, b.Class), stringValue(after, a.Class))
	}
	if absentSide || b.Endian != a.Endian {
		emit(model.FieldELFEndian, stringValue(before, b.Endian), stringValue(after, a.Endian))
	}
	if absentSide || b.Machine != a.Machine {
		bv, av := model.NullValue(), model.NullValue()
		if before != nil {
			bv = model.MachineValue(b.Machine)
		}
		if after != nil {
			av = model.MachineValue(a.Machine)
		}
		emit(model.FieldELFMachine, bv, av)
	}
	if absentSide || b.SONAME != a.SONAME {
		emit(model.FieldELFSONAME, stringValue(before, b.SONAME), stringValue(after, a.SONAME))
	}
	if absentSide || !slices.Equal(b.Needed, a.Needed) {
		bv, av := model.NullValue(), model.NullValue()
		if before != nil {
			bv = model.NeededValue(b.Needed)
		}
		if after != nil {
			av = model.NeededValue(a.Needed)
		}
		emit(model.FieldELFNeeded, bv, av)
	}
}
