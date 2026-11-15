// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package model defines FirmwareDelta's versioned, filesystem-independent contracts.
// Implementation packages depend on this package rather than the public facade.
package model

const (
	SchemaVersion  = 1
	MaxEntries     = 250_000
	MaxPathBytes   = 4096
	MaxPolicyBytes = 1 << 20
	MaxPolicyRules = 10_000
)

type Kind string

const (
	KindFile        Kind = "file"
	KindDirectory   Kind = "directory"
	KindSymlink     Kind = "symlink"
	KindBlockDevice Kind = "block_device"
	KindCharDevice  Kind = "char_device"
	KindFIFO        Kind = "fifo"
	KindSocket      Kind = "socket"
)

type Category string

const (
	CategoryConfig     Category = "config"
	CategoryLibrary    Category = "library"
	CategoryExecutable Category = "executable"
	CategoryOther      Category = "other"
)

// ELF contains only static metadata. An empty SONAME is distinct from no ELF.
// Machine is the numeric ELF e_machine value, including unfamiliar architectures.
type ELF struct {
	Class   string   `json:"class"`
	Endian  string   `json:"endian"`
	Machine uint16   `json:"machine"`
	SONAME  string   `json:"soname"`
	Needed  []string `json:"needed"`
}

// Entry describes one root-relative path. Mode is four octal digits containing
// Unix permission, setuid, setgid and sticky bits, without file-type bits.
// Size/SHA256 are present only for files; Target only for symlinks; ELF only for
// ELF files. Pointers distinguish absent metadata from empty/zero metadata.
type Entry struct {
	Path     string   `json:"path"`
	Kind     Kind     `json:"kind"`
	Mode     string   `json:"mode"`
	Category Category `json:"category"`
	Size     *int64   `json:"size,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Target   *string  `json:"target,omitempty"`
	ELF      *ELF     `json:"elf,omitempty"`
}

// Inventory excludes the root itself, its host location and volatile identity.
type Inventory struct {
	SchemaVersion int     `json:"schema_version"`
	Entries       []Entry `json:"entries"`
}

type Field string

const (
	FieldPresence   Field = "presence"
	FieldKind       Field = "kind"
	FieldContent    Field = "content"
	FieldMode       Field = "mode"
	FieldTarget     Field = "target"
	FieldELFClass   Field = "elf.class"
	FieldELFEndian  Field = "elf.endian"
	FieldELFMachine Field = "elf.machine"
	FieldELFSONAME  Field = "elf.soname"
	FieldELFNeeded  Field = "elf.needed"
)

type Content struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Change carries observed facts plus a policy decision. Before and After use
// Value's direct JSON encoding, not a tagged wrapper. Reason is set only when
// Expected is true. Category comes from the candidate, or baseline on removal.
type Change struct {
	Path     string   `json:"path"`
	Category Category `json:"category"`
	Field    Field    `json:"field"`
	Before   Value    `json:"before"`
	After    Value    `json:"after"`
	Expected bool     `json:"expected"`
	Reason   string   `json:"reason,omitempty"`
}

type Rule struct {
	Path   string  `json:"path"`
	Fields []Field `json:"fields"`
	Reason string  `json:"reason"`
}

type Policy struct {
	SchemaVersion int    `json:"schema_version"`
	Allow         []Rule `json:"allow"`
}

// Options.Policy nil means no allowances. A non-nil policy must validate,
// including policies built directly in Go rather than parsed from JSON.
type Options struct {
	Policy *Policy
}

type WarningCode string

const WarningUnusedRule WarningCode = "unused_rule"

// Warning identifies an allow rule that matched no observed path/field pair.
// It is information, not a change or an approval.
type Warning struct {
	Path string      `json:"path"`
	Code WarningCode `json:"code"`
}

type Counts struct {
	Total      int `json:"total"`
	Expected   int `json:"expected"`
	Unexpected int `json:"unexpected"`
}

type Verdict string

const (
	VerdictUnchanged         Verdict = "unchanged"
	VerdictExpectedChanges   Verdict = "expected_changes"
	VerdictUnexpectedChanges Verdict = "unexpected_changes"
)

type Report struct {
	SchemaVersion   int       `json:"schema_version"`
	BaselineDigest  string    `json:"baseline_digest"`
	CandidateDigest string    `json:"candidate_digest"`
	Changes         []Change  `json:"changes"`
	PolicyWarnings  []Warning `json:"policy_warnings"`
	Counts          Counts    `json:"counts"`
	Verdict         Verdict   `json:"verdict"`
}
