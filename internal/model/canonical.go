// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

func canonicalNames(names []string) []string {
	result := append([]string{}, names...)
	slices.Sort(result)
	return slices.Compact(result)
}

func cloneEntry(e Entry) Entry {
	if e.Size != nil {
		n := *e.Size
		e.Size = &n
	}
	if e.Target != nil {
		t := *e.Target
		e.Target = &t
	}
	if e.ELF != nil {
		elf := *e.ELF
		elf.Needed = canonicalNames(elf.Needed)
		e.ELF = &elf
	}
	return e
}

func normalizeValue(v Value) Value {
	if v.Entry != nil {
		return EntryValue(*v.Entry)
	}
	if v.Content != nil {
		return ContentValue(*v.Content)
	}
	if v.String != nil {
		return StringValue(*v.String)
	}
	if v.Machine != nil {
		return MachineValue(*v.Machine)
	}
	if v.Needed != nil {
		return NeededValue(*v.Needed)
	}
	return NullValue()
}

// NormalizeInventory validates and returns an independent canonical copy.
func NormalizeInventory(i Inventory) (Inventory, error) {
	if err := i.Validate(); err != nil {
		return Inventory{}, err
	}
	result := Inventory{SchemaVersion: SchemaVersion, Entries: make([]Entry, len(i.Entries))}
	for n, e := range i.Entries {
		result.Entries[n] = cloneEntry(e)
	}
	slices.SortFunc(result.Entries, func(a, b Entry) int { return compare(a.Path, b.Path) })
	return result, nil
}

// CanonicalInventoryJSON is encoding/json's compact encoding of the normalized
// Inventory struct, including schema_version and entries, with no trailing LF.
// Its property order and escaping are part of schema 1's digest contract.
func CanonicalInventoryJSON(i Inventory) ([]byte, error) {
	normal, err := NormalizeInventory(i)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normal)
}

func InventoryDigest(i Inventory) (string, error) {
	b, err := CanonicalInventoryJSON(i)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NormalizeReport validates and sorts facts without changing decisions, counts
// or verdict. Callers retain ownership of their original slices and pointers.
func NormalizeReport(r Report) (Report, error) {
	if err := r.Validate(); err != nil {
		return Report{}, err
	}
	result := r
	result.Changes = make([]Change, len(r.Changes))
	for n, c := range r.Changes {
		c.Before, c.After = normalizeValue(c.Before), normalizeValue(c.After)
		result.Changes[n] = c
	}
	slices.SortFunc(result.Changes, func(a, b Change) int {
		if n := compare(a.Path, b.Path); n != 0 {
			return n
		}
		return compare(string(a.Field), string(b.Field))
	})
	result.PolicyWarnings = append([]Warning{}, r.PolicyWarnings...)
	slices.SortFunc(result.PolicyWarnings, func(a, b Warning) int {
		if n := compare(a.Path, b.Path); n != 0 {
			return n
		}
		return compare(string(a.Code), string(b.Code))
	})
	return result, nil
}

func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
