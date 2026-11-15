// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidatePath checks slash-separated, root-relative Linux path notation.
// Backslashes and glob characters are literal filename characters. Invalid UTF-8
// cannot be represented losslessly in JSON and therefore fails explicitly.
func ValidatePath(p string) error {
	if len(p) == 0 || len(p) > MaxPathBytes || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
		return errors.New("path must be valid UTF-8, nonempty, NUL-free and at most 4096 bytes")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path must be relative with no empty, dot or traversal segments")
		}
	}
	return nil
}

func validText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
func validMode(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validCategory(c Category) bool {
	return c == CategoryConfig || c == CategoryLibrary || c == CategoryExecutable || c == CategoryOther
}
func validKind(k Kind) bool {
	switch k {
	case KindFile, KindDirectory, KindSymlink, KindBlockDevice, KindCharDevice, KindFIFO, KindSocket:
		return true
	}
	return false
}
func ValidField(f Field) bool {
	switch f {
	case FieldPresence, FieldKind, FieldContent, FieldMode, FieldTarget, FieldELFClass, FieldELFEndian, FieldELFMachine, FieldELFSONAME, FieldELFNeeded:
		return true
	}
	return false
}

func (e ELF) Validate() error {
	if e.Class != "32" && e.Class != "64" {
		return errors.New("ELF class must be 32 or 64")
	}
	if e.Endian != "little" && e.Endian != "big" {
		return errors.New("ELF endian must be little or big")
	}
	if !validText(e.SONAME) {
		return errors.New("invalid ELF SONAME text")
	}
	for _, n := range e.Needed {
		if !validText(n) {
			return errors.New("invalid ELF needed text")
		}
	}
	return nil
}

func (e Entry) Validate() error {
	if err := ValidatePath(e.Path); err != nil {
		return err
	}
	if !validKind(e.Kind) {
		return errors.New("unknown entry kind")
	}
	if !validMode(e.Mode) {
		return errors.New("mode must be four octal digits")
	}
	if !validCategory(e.Category) {
		return errors.New("unknown category")
	}
	if e.Kind == KindFile {
		if e.Size == nil || *e.Size < 0 || !validDigest(e.SHA256) || e.Target != nil {
			return errors.New("file requires nonnegative size and SHA-256, and cannot have target")
		}
		if e.ELF != nil {
			return e.ELF.Validate()
		}
		return nil
	}
	if e.Size != nil || e.SHA256 != "" || e.ELF != nil {
		return errors.New("non-file cannot have content or ELF metadata")
	}
	if e.Kind == KindSymlink {
		if e.Target == nil || !validText(*e.Target) {
			return errors.New("symlink requires a valid target")
		}
	} else if e.Target != nil {
		return errors.New("only symlinks have targets")
	}
	return nil
}

func (i Inventory) Validate() error {
	if i.SchemaVersion != SchemaVersion {
		return errors.New("unsupported inventory schema version")
	}
	if len(i.Entries) > MaxEntries {
		return fmt.Errorf("inventory entries: %w", ErrLimitExceeded)
	}
	seen := make(map[string]bool, len(i.Entries))
	for _, e := range i.Entries {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("entry %q: %w", e.Path, err)
		}
		if seen[e.Path] {
			return fmt.Errorf("duplicate inventory path %q", e.Path)
		}
		seen[e.Path] = true
	}
	return nil
}

func (p Policy) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return errors.New("unsupported policy schema version")
	}
	if len(p.Allow) > MaxPolicyRules {
		return fmt.Errorf("policy rules: %w", ErrLimitExceeded)
	}
	seen := make(map[string]bool, len(p.Allow))
	for _, r := range p.Allow {
		if err := ValidatePath(r.Path); err != nil {
			return fmt.Errorf("rule path: %w", err)
		}
		if seen[r.Path] {
			return fmt.Errorf("duplicate policy rule %q", r.Path)
		}
		seen[r.Path] = true
		if !validText(r.Reason) || strings.TrimSpace(r.Reason) == "" {
			return errors.New("rule requires a nonempty rationale")
		}
		if len(r.Fields) == 0 {
			return errors.New("rule requires at least one field")
		}
		fields := make(map[Field]bool, len(r.Fields))
		for _, f := range r.Fields {
			if !ValidField(f) || fields[f] {
				return errors.New("unknown or duplicate policy field")
			}
			fields[f] = true
		}
	}
	return nil
}

func (v Value) validateFor(f Field) error {
	k, _, err := v.member()
	if err != nil {
		return err
	}
	switch f {
	case FieldPresence:
		if k == "null" {
			return nil
		}
		fallthrough
	case FieldKind:
		if k == "entry" {
			return v.Entry.Validate()
		}
	case FieldContent:
		if k == "content" && v.Content.Size >= 0 && validDigest(v.Content.SHA256) {
			return nil
		}
	case FieldMode:
		if k == "string" && validMode(*v.String) {
			return nil
		}
	case FieldTarget:
		if k == "string" && validText(*v.String) {
			return nil
		}
	case FieldELFClass:
		if k == "null" || k == "string" && (*v.String == "32" || *v.String == "64") {
			return nil
		}
	case FieldELFEndian:
		if k == "null" || k == "string" && (*v.String == "little" || *v.String == "big") {
			return nil
		}
	case FieldELFMachine:
		if k == "null" || k == "machine" {
			return nil
		}
	case FieldELFSONAME:
		if k == "null" || k == "string" && validText(*v.String) {
			return nil
		}
	case FieldELFNeeded:
		if k == "null" {
			return nil
		}
		if k == "needed" {
			for _, n := range *v.Needed {
				if !validText(n) {
					return errors.New("invalid needed text")
				}
			}
			return nil
		}
	}
	return fmt.Errorf("invalid value shape for %s", f)
}

func (c Change) Validate() error {
	if err := ValidatePath(c.Path); err != nil {
		return err
	}
	if !validCategory(c.Category) || !ValidField(c.Field) {
		return errors.New("unknown category or change field")
	}
	if err := c.Before.validateFor(c.Field); err != nil {
		return fmt.Errorf("before: %w", err)
	}
	if err := c.After.validateFor(c.Field); err != nil {
		return fmt.Errorf("after: %w", err)
	}
	if c.Expected {
		if !validText(c.Reason) || strings.TrimSpace(c.Reason) == "" {
			return errors.New("expected change requires rationale")
		}
	} else if c.Reason != "" {
		return errors.New("unexpected change cannot have matched rationale")
	}
	if c.Field == FieldPresence || c.Field == FieldKind {
		if c.Field == FieldPresence && c.Before.IsNull() == c.After.IsNull() {
			return errors.New("presence requires exactly one absent side")
		}
		for _, e := range []*Entry{c.Before.Entry, c.After.Entry} {
			if e != nil && e.Path != c.Path {
				return errors.New("entry path differs from change path")
			}
		}
		chosen := c.After.Entry
		if chosen == nil {
			chosen = c.Before.Entry
		}
		if chosen.Category != c.Category {
			return errors.New("change category differs from selected entry")
		}
		if c.Field == FieldKind && c.Before.Entry.Kind == c.After.Entry.Kind {
			return errors.New("kind record requires different kinds")
		}
	}
	// Compare normalized values so a reordered DT_NEEDED set is not a change.
	b, _ := normalizeValue(c.Before).MarshalJSON()
	a, _ := normalizeValue(c.After).MarshalJSON()
	if bytes.Equal(b, a) {
		return errors.New("change has equal before and after values")
	}
	return nil
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return errors.New("unsupported report schema version")
	}
	if !validDigest(r.BaselineDigest) || !validDigest(r.CandidateDigest) {
		return errors.New("report requires canonical SHA-256 inventory digests")
	}
	seen := make(map[string]bool, len(r.Changes))
	expected := 0
	for _, c := range r.Changes {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("change %q %s: %w", c.Path, c.Field, err)
		}
		key := c.Path + "\x00" + string(c.Field)
		if seen[key] {
			return errors.New("duplicate path/field change")
		}
		seen[key] = true
		if c.Expected {
			expected++
		}
	}
	if r.Counts != (Counts{Total: len(r.Changes), Expected: expected, Unexpected: len(r.Changes) - expected}) {
		return errors.New("report counts do not match changes")
	}
	warnings := make(map[string]bool, len(r.PolicyWarnings))
	for _, w := range r.PolicyWarnings {
		if err := ValidatePath(w.Path); err != nil {
			return fmt.Errorf("warning path: %w", err)
		}
		if w.Code != WarningUnusedRule || warnings[w.Path] {
			return errors.New("unknown or duplicate policy warning")
		}
		warnings[w.Path] = true
	}
	want := VerdictUnchanged
	if r.Counts.Unexpected > 0 {
		want = VerdictUnexpectedChanges
	} else if r.Counts.Total > 0 {
		want = VerdictExpectedChanges
	}
	if r.Verdict != want {
		return errors.New("verdict does not match change counts")
	}
	return nil
}
