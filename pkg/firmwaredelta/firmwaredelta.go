// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package firmwaredelta compares two immutable extracted firmware directories
// on Linux amd64. Compare collects static filesystem/ELF metadata, reports every
// observed atomic difference and applies optional exact-path/field allowances.
// It never runs firmware programs, follows child symlinks, writes inputs or
// accesses the network. Inputs must remain quiescent: mutation detection is not
// an atomic filesystem snapshot. Expected changes acknowledge a policy rule;
// they do not establish safety, ABI compatibility or runtime behavior.
//
// ReadPolicy and the writers are host-independent. Compare returns InputError,
// ScanError or PolicyError; errors.As identifies their types and errors.Is
// preserves cancellation, deadlines and the exported sentinel errors. No API
// entrypoint prints or exits. A comparison failure returns an empty Report.
package firmwaredelta

import (
	"context"
	"errors"
	"io"

	"github.com/firmdura/firmwaredelta/internal/delta"
	"github.com/firmdura/firmwaredelta/internal/inventory"
	"github.com/firmdura/firmwaredelta/internal/model"
	"github.com/firmdura/firmwaredelta/internal/policy"
	"github.com/firmdura/firmwaredelta/internal/render"
)

// Public aliases allow callers to inspect evidence, construct policies and
// handle errors without importing implementation packages.
type (
	Kind        = model.Kind
	Category    = model.Category
	ELF         = model.ELF
	Entry       = model.Entry
	Inventory   = model.Inventory
	Field       = model.Field
	Content     = model.Content
	Value       = model.Value
	Change      = model.Change
	Rule        = model.Rule
	Policy      = model.Policy
	Options     = model.Options
	WarningCode = model.WarningCode
	Warning     = model.Warning
	Counts      = model.Counts
	Verdict     = model.Verdict
	Report      = model.Report
	InputError  = model.InputError
	ScanError   = model.ScanError
	PolicyError = model.PolicyError
)

// Schema and resource limits apply to each comparison and policy.
const (
	SchemaVersion  = model.SchemaVersion
	MaxEntries     = model.MaxEntries
	MaxPathBytes   = model.MaxPathBytes
	MaxPolicyBytes = model.MaxPolicyBytes
	MaxPolicyRules = model.MaxPolicyRules
)

// Entry kinds describe filesystem metadata, not executable behavior.
const (
	KindFile        = model.KindFile
	KindDirectory   = model.KindDirectory
	KindSymlink     = model.KindSymlink
	KindBlockDevice = model.KindBlockDevice
	KindCharDevice  = model.KindCharDevice
	KindFIFO        = model.KindFIFO
	KindSocket      = model.KindSocket
)

// Categories are review aids, without risk or compatibility conclusions.
const (
	CategoryConfig     = model.CategoryConfig
	CategoryLibrary    = model.CategoryLibrary
	CategoryExecutable = model.CategoryExecutable
	CategoryOther      = model.CategoryOther
)

// Fields are the exact atomic names accepted by policy rules.
const (
	FieldPresence   = model.FieldPresence
	FieldKind       = model.FieldKind
	FieldContent    = model.FieldContent
	FieldMode       = model.FieldMode
	FieldTarget     = model.FieldTarget
	FieldELFClass   = model.FieldELFClass
	FieldELFEndian  = model.FieldELFEndian
	FieldELFMachine = model.FieldELFMachine
	FieldELFSONAME  = model.FieldELFSONAME
	FieldELFNeeded  = model.FieldELFNeeded
)

// Verdicts summarize atomic change counts. Unused rules do not affect verdicts.
const (
	VerdictUnchanged         = model.VerdictUnchanged
	VerdictExpectedChanges   = model.VerdictExpectedChanges
	VerdictUnexpectedChanges = model.VerdictUnexpectedChanges
	WarningUnusedRule        = model.WarningUnusedRule
)

// Sentinels remain discoverable through wrapped errors with errors.Is.
var (
	ErrLimitExceeded   = model.ErrLimitExceeded
	ErrInputChanged    = model.ErrInputChanged
	ErrUnsupportedHost = model.ErrUnsupportedHost
)

// ReadPolicy parses one bounded schema-1 JSON policy, rejecting duplicate keys,
// unknown members and invalid exact path/field rules. Errors are PolicyError.
func ReadPolicy(r io.Reader) (Policy, error) { return policy.Read(r) }

// Compare validates options, scans both roots, compares all evidence and applies
// the optional policy. A nil policy allows nothing. Context cancellation stops
// scanning and remains discoverable with errors.Is; no partial report returns.
func Compare(ctx context.Context, baselineRoot, candidateRoot string, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, &InputError{Op: "compare", Err: errors.New("a context is required")}
	}
	if err := canceled(ctx); err != nil {
		return Report{}, err
	}
	if options.Policy != nil {
		if err := options.Policy.Validate(); err != nil {
			return Report{}, &PolicyError{Op: "validate", Err: err}
		}
	}
	baseline, err := inventory.Scan(ctx, baselineRoot)
	if err != nil {
		return Report{}, err
	}
	candidate, err := inventory.Scan(ctx, candidateRoot)
	if err != nil {
		return Report{}, err
	}
	if err := canceled(ctx); err != nil {
		return Report{}, err
	}
	report, err := delta.Compare(baseline, candidate)
	if err != nil {
		return Report{}, err
	}
	if err := canceled(ctx); err != nil {
		return Report{}, err
	}
	report, err = policy.Apply(report, options.Policy)
	if err != nil {
		return Report{}, err
	}
	if err := canceled(ctx); err != nil {
		return Report{}, err
	}
	return report, nil
}

func canceled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &ScanError{Op: "compare", Err: err}
	}
	return nil
}

// WriteJSON validates and normalizes report, then writes compact schema-1 JSON
// with a trailing newline. Invalid reports produce no output; I/O errors return.
func WriteJSON(w io.Writer, report Report) error { return render.WriteJSON(w, report) }

// WriteMarkdown validates and normalizes report, then writes all facts and policy
// decisions with inert caller text. Invalid reports produce no output.
func WriteMarkdown(w io.Writer, report Report) error { return render.WriteMarkdown(w, report) }

// Value constructors copy their evidence, including nested entry metadata.
func NullValue() Value             { return model.NullValue() }
func EntryValue(e Entry) Value     { return model.EntryValue(e) }
func ContentValue(c Content) Value { return model.ContentValue(c) }
func StringValue(s string) Value   { return model.StringValue(s) }
func MachineValue(n uint16) Value  { return model.MachineValue(n) }
func NeededValue(names []string) Value {
	return model.NeededValue(names)
}
