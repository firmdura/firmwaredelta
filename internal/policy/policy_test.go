// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/firmdura/firmwaredelta/internal/model"
	"github.com/firmdura/firmwaredelta/internal/policy"
)

const validPolicy = `{"schema_version":1,"allow":[{"path":"usr/bin/demo","fields":["content"],"reason":"Approved maintenance rebuild"}]}`

func TestReadValidPolicies(t *testing.T) {
	tests := []struct {
		name, data string
		want       model.Policy
	}{
		{"normal", validPolicy, model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "usr/bin/demo", Fields: []model.Field{model.FieldContent}, Reason: "Approved maintenance rebuild"}}}},
		{"empty", `{"schema_version":1,"allow":[]}`, model.Policy{SchemaVersion: 1, Allow: []model.Rule{}}},
		{"order and escapes", `{"allow":[{"reason":"pair \ud83d\ude00 and \\ud800","fields":["mode"],"p\u0061th":"etc/\ud83d\ude00"}],"schema_version":1}`, model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "etc/😀", Fields: []model.Field{model.FieldMode}, Reason: "pair 😀 and \\ud800"}}}},
		{"literal path characters", `{"schema_version":1,"allow":[{"path":"etc/a\\b*[x]\nfile","fields":["target"],"reason":"  exact literal name  "}]}`, model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "etc/a\\b*[x]\nfile", Fields: []model.Field{model.FieldTarget}, Reason: "  exact literal name  "}}}},
		{"all atomic fields", `{"schema_version":1,"allow":[{"path":"x","fields":["presence","kind","content","mode","target","elf.class","elf.endian","elf.machine","elf.soname","elf.needed"],"reason":"reviewed"}]}`, model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{model.FieldPresence, model.FieldKind, model.FieldContent, model.FieldMode, model.FieldTarget, model.FieldELFClass, model.FieldELFEndian, model.FieldELFMachine, model.FieldELFSONAME, model.FieldELFNeeded}, Reason: "reviewed"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.Read(strings.NewReader(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestReadRejectsInvalidDocuments(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "null root": "null", "array root": "[]", "truncated": `{"schema_version":1,"allow":[`,
		"missing version": `{"allow":[]}`, "missing allow": `{"schema_version":1}`, "null allow": `{"schema_version":1,"allow":null}`,
		"wrong version": `{"schema_version":2,"allow":[]}`, "string version": `{"schema_version":"1","allow":[]}`, "null version": `{"schema_version":null,"allow":[]}`,
		"unknown top member": `{"schema_version":1,"allow":[],"rules":[]}`, "case alias": `{"Schema_Version":1,"allow":[]}`,
		"duplicate version": `{"schema_version":1,"schema_version":1,"allow":[]}`, "duplicate allow": `{"schema_version":1,"allow":[],"allow":[]}`,
		"escaped duplicate version": `{"schema_version":1,"schema_\u0076ersion":1,"allow":[]}`,
		"duplicate path":            strings.Replace(validPolicy, `"path":"usr/bin/demo"`, `"path":"usr/bin/demo","path":"usr/bin/demo"`, 1),
		"escaped duplicate path":    strings.Replace(validPolicy, `"path":"usr/bin/demo"`, `"path":"usr/bin/demo","p\u0061th":"usr/bin/demo"`, 1),
		"duplicate fields":          strings.Replace(validPolicy, `"fields":["content"]`, `"fields":["content"],"fields":["mode"]`, 1),
		"duplicate reason":          strings.Replace(validPolicy, `"reason":`, `"reason":"other","reason":`, 1),
		"unknown rule member":       strings.Replace(validPolicy, `"path":`, `"pattern":"*","path":`, 1),
		"missing rule path":         `{"schema_version":1,"allow":[{"fields":["content"],"reason":"r"}]}`,
		"missing rule fields":       `{"schema_version":1,"allow":[{"path":"x","reason":"r"}]}`,
		"missing rule reason":       `{"schema_version":1,"allow":[{"path":"x","fields":["content"]}]}`,
		"null rule":                 `{"schema_version":1,"allow":[null]}`, "array rule": `{"schema_version":1,"allow":[[]]}`,
		"null fields": strings.Replace(validPolicy, `["content"]`, `null`, 1), "empty fields": strings.Replace(validPolicy, `["content"]`, `[]`, 1),
		"unknown field": strings.Replace(validPolicy, `"content"`, `"size"`, 1), "duplicate field": strings.Replace(validPolicy, `["content"]`, `["content","content"]`, 1),
		"null field": strings.Replace(validPolicy, `["content"]`, `[null]`, 1), "nested field": strings.Replace(validPolicy, `["content"]`, `[{"x":1}]`, 1),
		"null reason":       strings.Replace(validPolicy, `"Approved maintenance rebuild"`, `null`, 1),
		"empty reason":      strings.Replace(validPolicy, `"Approved maintenance rebuild"`, `""`, 1),
		"whitespace reason": strings.Replace(validPolicy, `"Approved maintenance rebuild"`, `" \t\n\u00a0\u3000"`, 1),
		"NUL reason":        strings.Replace(validPolicy, `"Approved maintenance rebuild"`, `"review\u0000"`, 1),
		"number path":       strings.Replace(validPolicy, `"usr/bin/demo"`, `123`, 1),
		"trailing value":    validPolicy + ` {}`, "trailing garbage": validPolicy + ` no`, "trailing comma": `{"schema_version":1,"allow":[],}`,
		"invalid UTF8":                  strings.Replace(validPolicy, "usr/bin/demo", "usr/\xff", 1),
		"unpaired high surrogate path":  strings.Replace(validPolicy, "usr/bin/demo", `usr/\ud800`, 1),
		"unpaired low surrogate reason": strings.Replace(validPolicy, "Approved maintenance rebuild", `\udc00`, 1),
		"bad surrogate pair":            strings.Replace(validPolicy, "usr/bin/demo", `usr/\ud800\u0041`, 1),
	} {
		t.Run(name, func(t *testing.T) { requirePolicyError(t, input, nil) })
	}
	for _, path := range []string{"", "/x", "x/", ".", "..", "./x", "x/..", "x/../y", "x//y", "x/./y", "x\x00y", strings.Repeat("x", model.MaxPathBytes+1), strings.Repeat("é", model.MaxPathBytes/2+1)} {
		t.Run(fmt.Sprintf("invalid path %q", abbreviate(path)), func(t *testing.T) {
			encoded, err := json.Marshal(path)
			if err != nil {
				t.Fatal(err)
			}
			requirePolicyError(t, strings.Replace(validPolicy, `"usr/bin/demo"`, string(encoded), 1), nil)
		})
	}
	duplicate := `{"schema_version":1,"allow":[{"path":"x","fields":["content"],"reason":"first"},{"path":"x","fields":["mode"],"reason":"second"}]}`
	requirePolicyError(t, duplicate, nil)
}

func TestReadLimitBoundaries(t *testing.T) {
	const empty = `{"schema_version":1,"allow":[]}`
	for _, size := range []int{model.MaxPolicyBytes - 1, model.MaxPolicyBytes, model.MaxPolicyBytes + 1} {
		t.Run(fmt.Sprintf("bytes %d", size), func(t *testing.T) {
			input := empty + strings.Repeat(" ", size-len(empty))
			if size > model.MaxPolicyBytes {
				requirePolicyError(t, input, model.ErrLimitExceeded)
			} else if _, err := policy.Read(strings.NewReader(input)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, count := range []int{model.MaxPolicyRules - 1, model.MaxPolicyRules, model.MaxPolicyRules + 1} {
		t.Run(fmt.Sprintf("rules %d", count), func(t *testing.T) {
			var data strings.Builder
			data.WriteString(`{"schema_version":1,"allow":[`)
			for i := 0; i < count; i++ {
				if i > 0 {
					data.WriteByte(',')
				}
				fmt.Fprintf(&data, `{"path":"p%05d","fields":["content"],"reason":"r"}`, i)
			}
			data.WriteString(`]}`)
			if data.Len() >= model.MaxPolicyBytes {
				t.Fatal("rule test must stay below byte limit")
			}
			if count > model.MaxPolicyRules {
				requirePolicyError(t, data.String(), model.ErrLimitExceeded)
			} else {
				got, err := policy.Read(strings.NewReader(data.String()))
				if err != nil || len(got.Allow) != count {
					t.Fatalf("rules = %d, error = %v", len(got.Allow), err)
				}
			}
		})
	}
	for _, path := range []string{strings.Repeat("x", model.MaxPathBytes), strings.Repeat("é", model.MaxPathBytes/2)} {
		encoded, _ := json.Marshal(path)
		if _, err := policy.Read(strings.NewReader(strings.Replace(validPolicy, `"usr/bin/demo"`, string(encoded), 1))); err != nil {
			t.Fatalf("exact path byte boundary: %v", err)
		}
	}
}

func TestReadReaderFailuresAndBoundedConsumption(t *testing.T) {
	want := errors.New("reader unavailable")
	for name, r := range map[string]io.Reader{
		"nil":                              nil,
		"failure":                          failingReader{err: want},
		"valid bytes and failure together": failingReader{data: validPolicy, err: want},
		"failure after valid document":     io.MultiReader(strings.NewReader(validPolicy), failingReader{err: want}),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := policy.Read(r)
			var typed *model.PolicyError
			if !errors.As(err, &typed) || !reflect.DeepEqual(p, model.Policy{}) {
				t.Fatalf("policy = %#v, error = %v", p, err)
			}
			if name != "nil" && !errors.Is(err, want) {
				t.Fatalf("reader error lost: %v", err)
			}
		})
	}
	r := strings.NewReader(strings.Repeat(" ", model.MaxPolicyBytes+100))
	_, err := policy.Read(r)
	if !errors.Is(err, model.ErrLimitExceeded) || r.Len() != 99 {
		t.Fatalf("limit error = %v, unread bytes = %d", err, r.Len())
	}
}

func TestApplyExactPathAndFieldDefaultDeny(t *testing.T) {
	report := makeReport(
		contentChange("usr/bin/demo"), modeChange("usr/bin/demo"), neededChange("usr/bin/demo"),
		contentChange("usr/bin/demo-extra"), contentChange("usr/bin/demo/child"), contentChange("usr/bin/dem"),
		contentChange("etc/config"), contentChange("usr/bin/*"),
	)
	p := model.Policy{SchemaVersion: 1, Allow: []model.Rule{
		{Path: "usr/bin/demo", Fields: []model.Field{model.FieldContent}, Reason: "Approved rebuild"},
		{Path: "usr/bin/*", Fields: []model.Field{model.FieldContent}, Reason: "Literal star path only"},
		{Path: "usr/bin", Fields: []model.Field{model.FieldContent}, Reason: "Not a prefix"},
		{Path: "unused-z", Fields: []model.Field{model.FieldContent}, Reason: "unused"},
		{Path: "etc/config", Fields: []model.Field{model.FieldMode}, Reason: "Unobserved field"},
		{Path: "unused-a", Fields: []model.Field{model.FieldContent}, Reason: "unused"},
	}}
	got, err := policy.Apply(report, &p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Counts != (model.Counts{Total: 8, Expected: 2, Unexpected: 6}) || got.Verdict != model.VerdictUnexpectedChanges {
		t.Fatalf("counts/verdict: %#v %s", got.Counts, got.Verdict)
	}
	for _, change := range got.Changes {
		wantReason := ""
		if change.Path == "usr/bin/demo" && change.Field == model.FieldContent {
			wantReason = "Approved rebuild"
		} else if change.Path == "usr/bin/*" {
			wantReason = "Literal star path only"
		}
		if change.Expected != (wantReason != "") || change.Reason != wantReason {
			t.Errorf("incorrect decision: %#v", change)
		}
	}
	warnings := []model.Warning{{Path: "etc/config", Code: model.WarningUnusedRule}, {Path: "unused-a", Code: model.WarningUnusedRule}, {Path: "unused-z", Code: model.WarningUnusedRule}, {Path: "usr/bin", Code: model.WarningUnusedRule}}
	if !reflect.DeepEqual(got.PolicyWarnings, warnings) {
		t.Fatalf("warnings = %#v", got.PolicyWarnings)
	}
	denied, err := policy.Apply(got, nil)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Counts != (model.Counts{Total: 8, Unexpected: 8}) || len(denied.PolicyWarnings) != 0 {
		t.Fatalf("nil policy retained decisions: %#v", denied)
	}
	for _, c := range denied.Changes {
		if c.Expected || c.Reason != "" {
			t.Errorf("stale decision: %#v", c)
		}
	}
	if !reflect.DeepEqual(denied, mustApply(t, got, &model.Policy{SchemaVersion: 1})) {
		t.Fatal("empty and absent policies disagree")
	}
}

func TestApplyPresenceKindAndAllVerdicts(t *testing.T) {
	file := fileEntry("usr/bin/demo")
	directory := model.Entry{Path: file.Path, Kind: model.KindDirectory, Mode: "0755", Category: model.CategoryOther}
	tests := []model.Change{
		{Path: file.Path, Category: file.Category, Field: model.FieldPresence, Before: model.NullValue(), After: model.EntryValue(file)},
		{Path: file.Path, Category: file.Category, Field: model.FieldPresence, Before: model.EntryValue(file), After: model.NullValue()},
		{Path: file.Path, Category: directory.Category, Field: model.FieldKind, Before: model.EntryValue(file), After: model.EntryValue(directory)},
	}
	for _, change := range tests {
		p := model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: change.Path, Fields: []model.Field{change.Field}, Reason: "Specifically acknowledged"}}}
		got := mustApply(t, makeReport(change), &p)
		if got.Counts != (model.Counts{Total: 1, Expected: 1}) || got.Verdict != model.VerdictExpectedChanges || got.Changes[0].Reason != p.Allow[0].Reason {
			t.Fatalf("wrong acknowledged verdict: %#v", got)
		}
		p.Allow[0].Fields = []model.Field{model.FieldContent}
		got = mustApply(t, makeReport(change), &p)
		if got.Verdict != model.VerdictUnexpectedChanges || got.Counts.Expected != 0 || len(got.PolicyWarnings) != 1 {
			t.Fatalf("content allowed kind/presence: %#v", got)
		}
	}
	p := model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "unused", Fields: []model.Field{model.FieldPresence}, Reason: "unused"}}}
	got := mustApply(t, makeReport(), &p)
	if got.Verdict != model.VerdictUnchanged || got.Counts != (model.Counts{}) || len(got.PolicyWarnings) != 1 {
		t.Fatalf("empty report: %#v", got)
	}
}

func TestApplyRejectsConstructedPoliciesAndInvalidReports(t *testing.T) {
	report := makeReport(contentChange("x"))
	for name, p := range map[string]model.Policy{
		"version":             {},
		"bad path":            {SchemaVersion: 1, Allow: []model.Rule{{Path: "../x", Fields: []model.Field{model.FieldContent}, Reason: "r"}}},
		"missing reason":      {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{model.FieldContent}}}},
		"invalid UTF8 reason": {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{model.FieldContent}, Reason: "\xff"}}},
		"missing fields":      {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Reason: "r"}}},
		"unknown field":       {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{"unknown"}, Reason: "r"}}},
		"duplicate fields":    {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{model.FieldContent, model.FieldContent}, Reason: "r"}}},
		"duplicate paths":     {SchemaVersion: 1, Allow: []model.Rule{{Path: "x", Fields: []model.Field{model.FieldContent}, Reason: "r"}, {Path: "x", Fields: []model.Field{model.FieldMode}, Reason: "r"}}},
	} {
		t.Run(name, func(t *testing.T) {
			requireApplyError(t, report, &p, nil)
			// No observed changes do not excuse an invalid supplied policy.
			requireApplyError(t, makeReport(), &p, nil)
		})
	}
	p := model.Policy{SchemaVersion: 1, Allow: make([]model.Rule, model.MaxPolicyRules+1)}
	requireApplyError(t, report, &p, model.ErrLimitExceeded)
	for name, corrupt := range map[string]func(*model.Report){
		"version":        func(r *model.Report) { r.SchemaVersion = 2 },
		"digest":         func(r *model.Report) { r.BaselineDigest = "bad" },
		"counts":         func(r *model.Report) { r.Counts.Total++ },
		"verdict":        func(r *model.Report) { r.Verdict = model.VerdictUnchanged },
		"equal evidence": func(r *model.Report) { r.Changes[0].After = r.Changes[0].Before },
		"field":          func(r *model.Report) { r.Changes[0].Field = "size" },
		"stale reason":   func(r *model.Report) { r.Changes[0].Reason = "unmatched" },
		"duplicate record": func(r *model.Report) {
			r.Changes = append(r.Changes, r.Changes[0])
			r.Counts = model.Counts{Total: 2, Unexpected: 2}
		},
		"invalid old warning": func(r *model.Report) { r.PolicyWarnings = []model.Warning{{Path: "x", Code: "unrecognized"}} },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeReport(contentChange("x"))
			corrupt(&r)
			requireApplyError(t, r, nil, nil)
		})
	}
}

func TestApplyIndependentEvidenceAndDeterminism(t *testing.T) {
	entry := fileEntry("a")
	entry.ELF = &model.ELF{Class: "64", Endian: "little", Machine: 62, SONAME: "demo.so", Needed: []string{"libz.so", "liba.so"}}
	target := "old"
	link := model.Entry{Path: "link", Kind: model.KindSymlink, Mode: "0777", Category: model.CategoryOther, Target: &target}
	report := makeReport(
		contentChange("b"), modeChange("b"), neededChange("b"),
		model.Change{Path: "a", Category: entry.Category, Field: model.FieldPresence, After: model.EntryValue(entry)},
		model.Change{Path: "link", Category: link.Category, Field: model.FieldPresence, After: model.EntryValue(link)},
		model.Change{Path: "b", Category: model.CategoryOther, Field: model.FieldELFMachine, Before: model.MachineValue(3), After: model.MachineValue(62)},
	)
	pol := model.Policy{SchemaVersion: 1, Allow: []model.Rule{{Path: "b", Fields: []model.Field{model.FieldContent}, Reason: "rebuild"}, {Path: "z", Fields: []model.Field{model.FieldMode}, Reason: "unused"}, {Path: "c", Fields: []model.Field{model.FieldPresence}, Reason: "unused"}}}
	beforeReport, beforePolicy := encoded(t, report), encoded(t, pol)
	got := mustApply(t, report, &pol)
	if !bytes.Equal(beforeReport, encoded(t, report)) || !bytes.Equal(beforePolicy, encoded(t, pol)) {
		t.Fatal("application changed arguments")
	}
	if twice := mustApply(t, got, &pol); !reflect.DeepEqual(got, twice) {
		t.Fatal("repeated application differs")
	}
	slices.Reverse(report.Changes)
	slices.Reverse(pol.Allow)
	if shuffled := mustApply(t, report, &pol); !reflect.DeepEqual(got, shuffled) {
		t.Fatal("input order changed output")
	}
	// Mutating every pointer-bearing evidence shape in the result cannot reach
	// the caller's original report or the policy.
	beforeReport, beforePolicy = encoded(t, report), encoded(t, pol)
	for i := range got.Changes {
		c := &got.Changes[i]
		for _, v := range []*model.Value{&c.Before, &c.After} {
			switch {
			case v.Content != nil:
				v.Content.Size++
			case v.String != nil:
				*v.String = "changed"
			case v.Machine != nil:
				*v.Machine = 99
			case v.Needed != nil:
				(*v.Needed)[0] = "changed"
			case v.Entry != nil:
				v.Entry.Mode = "0000"
				if v.Entry.Size != nil {
					*v.Entry.Size++
				}
				if v.Entry.ELF != nil {
					v.Entry.ELF.Needed[0] = "changed"
				}
				if v.Entry.Target != nil {
					*v.Entry.Target = "changed"
				}
			}
		}
	}
	got.PolicyWarnings[0].Path = "changed"
	if !bytes.Equal(beforeReport, encoded(t, report)) || !bytes.Equal(beforePolicy, encoded(t, pol)) {
		t.Fatal("output retained caller-owned pointers/slices")
	}
}

type failingReader struct {
	data string
	err  error
}

func (r failingReader) Read(p []byte) (int, error) { return copy(p, r.data), r.err }

func abbreviate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func requirePolicyError(t *testing.T, input string, cause error) {
	t.Helper()
	p, err := policy.Read(strings.NewReader(input))
	var typed *model.PolicyError
	if !errors.As(err, &typed) || !reflect.DeepEqual(p, model.Policy{}) {
		t.Fatalf("expected no policy and typed error, got %#v, %v", p, err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("missing cause %v: %v", cause, err)
	}
}

func requireApplyError(t *testing.T, r model.Report, p *model.Policy, cause error) {
	t.Helper()
	got, err := policy.Apply(r, p)
	var typed *model.PolicyError
	if !errors.As(err, &typed) || !reflect.DeepEqual(got, model.Report{}) {
		t.Fatalf("expected no report and typed error, got %#v, %v", got, err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("missing cause %v: %v", cause, err)
	}
}

func mustApply(t *testing.T, r model.Report, p *model.Policy) model.Report {
	t.Helper()
	got, err := policy.Apply(r, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("application produced invalid report: %v", err)
	}
	return got
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func makeReport(changes ...model.Change) model.Report {
	r := model.Report{SchemaVersion: 1, BaselineDigest: strings.Repeat("a", 64), CandidateDigest: strings.Repeat("b", 64), Changes: changes, PolicyWarnings: []model.Warning{}, Counts: model.Counts{Total: len(changes), Unexpected: len(changes)}, Verdict: model.VerdictUnchanged}
	if len(changes) > 0 {
		r.Verdict = model.VerdictUnexpectedChanges
	}
	return r
}

func fileEntry(path string) model.Entry {
	size := int64(10)
	return model.Entry{Path: path, Kind: model.KindFile, Mode: "0644", Category: model.CategoryOther, Size: &size, SHA256: strings.Repeat("a", 64)}
}

func contentChange(path string) model.Change {
	return model.Change{Path: path, Category: model.CategoryOther, Field: model.FieldContent, Before: model.ContentValue(model.Content{Size: 10, SHA256: strings.Repeat("a", 64)}), After: model.ContentValue(model.Content{Size: 11, SHA256: strings.Repeat("b", 64)})}
}

func modeChange(path string) model.Change {
	return model.Change{Path: path, Category: model.CategoryOther, Field: model.FieldMode, Before: model.StringValue("0644"), After: model.StringValue("0755")}
}

func neededChange(path string) model.Change {
	return model.Change{Path: path, Category: model.CategoryOther, Field: model.FieldELFNeeded, Before: model.NeededValue([]string{"libc.so"}), After: model.NeededValue([]string{"libc.so", "libextra.so"})}
}
