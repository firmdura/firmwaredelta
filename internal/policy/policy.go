// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package policy parses bounded schema-1 policies and acknowledges individual
// observed path/field pairs. An allowance is not a safety judgment about bytes.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/firmdura/firmwaredelta/internal/model"
)

// Read parses exactly one policy document. All members are required, member
// names are case-sensitive, and duplicate keys (including escaped aliases),
// unknown members and lossy Unicode strings are rejected. The byte limit
// includes trailing whitespace. Errors never return a partially usable policy.
func Read(r io.Reader) (model.Policy, error) {
	if r == nil {
		return model.Policy{}, policyError("read", errors.New("nil reader"))
	}
	data, err := io.ReadAll(io.LimitReader(r, model.MaxPolicyBytes+1))
	if err != nil {
		return model.Policy{}, policyError("read", err)
	}
	if len(data) > model.MaxPolicyBytes {
		return model.Policy{}, policyError("read", fmt.Errorf("policy bytes: %w", model.ErrLimitExceeded))
	}
	if !utf8.Valid(data) || !validUnicodeEscapes(data) {
		return model.Policy{}, policyError("read", errors.New("policy must contain lossless Unicode text"))
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	p := model.Policy{}
	err = readObject(d, []string{"schema_version", "allow"}, func(key string) error {
		switch key {
		case "schema_version":
			t, err := d.Token()
			if err != nil {
				return err
			}
			n, ok := t.(json.Number)
			if !ok {
				return errors.New("schema_version must be an integer")
			}
			p.SchemaVersion, err = strconv.Atoi(string(n))
			return err
		case "allow":
			var err error
			p.Allow, err = readRules(d)
			return err
		}
		return nil
	})
	if err == nil {
		if _, trailing := d.Token(); trailing != io.EOF {
			err = errors.New("trailing policy data")
		}
	}
	if err == nil {
		err = p.Validate()
	}
	if err != nil {
		return model.Policy{}, policyError("read", err)
	}
	return p, nil
}

// Apply validates the complete report and policy before recomputing decisions.
// A nil policy allows nothing. The result owns independent evidence, records
// and warnings; neither argument is changed. Only exact path/field matches are
// expected, and a rule is unused unless at least one such pair was observed.
func Apply(report model.Report, policy *model.Policy) (model.Report, error) {
	if policy != nil {
		if err := policy.Validate(); err != nil {
			return model.Report{}, policyError("apply", err)
		}
	}
	result, err := model.NormalizeReport(report)
	if err != nil {
		return model.Report{}, policyError("apply", err)
	}
	type allowance struct {
		fields map[model.Field]bool
		reason string
		used   bool
	}
	rules := make(map[string]*allowance)
	if policy != nil {
		for _, rule := range policy.Allow {
			fields := make(map[model.Field]bool, len(rule.Fields))
			for _, field := range rule.Fields {
				fields[field] = true
			}
			rules[rule.Path] = &allowance{fields: fields, reason: rule.Reason}
		}
	}
	result.Counts = model.Counts{Total: len(result.Changes)}
	result.PolicyWarnings = []model.Warning{}
	for i := range result.Changes {
		change := &result.Changes[i]
		change.Expected, change.Reason = false, ""
		if rule := rules[change.Path]; rule != nil && rule.fields[change.Field] {
			change.Expected, change.Reason, rule.used = true, rule.reason, true
			result.Counts.Expected++
		} else {
			result.Counts.Unexpected++
		}
	}
	for path, rule := range rules {
		if !rule.used {
			result.PolicyWarnings = append(result.PolicyWarnings, model.Warning{Path: path, Code: model.WarningUnusedRule})
		}
	}
	result.Verdict = model.VerdictUnchanged
	if result.Counts.Unexpected > 0 {
		result.Verdict = model.VerdictUnexpectedChanges
	} else if result.Counts.Expected > 0 {
		result.Verdict = model.VerdictExpectedChanges
	}
	// Sort warnings without repairing invalid observations or classifications.
	result, err = model.NormalizeReport(result)
	if err != nil {
		return model.Report{}, policyError("apply", err)
	}
	return result, nil
}

func policyError(op string, err error) error { return &model.PolicyError{Op: op, Err: err} }

func readObject(d *json.Decoder, keys []string, readMember func(string) error) error {
	if err := delimiter(d, '{'); err != nil {
		return err
	}
	seen := make(map[string]bool, len(keys))
	for d.More() {
		key, err := readString(d)
		if err != nil {
			return err
		}
		known := false
		for _, allowed := range keys {
			if key == allowed {
				known = true
				break
			}
		}
		if !known {
			return errors.New("unknown policy member")
		}
		if seen[key] {
			return errors.New("duplicate policy member")
		}
		seen[key] = true
		if err := readMember(key); err != nil {
			return err
		}
	}
	if err := delimiter(d, '}'); err != nil {
		return err
	}
	if len(seen) != len(keys) {
		return errors.New("missing policy member")
	}
	return nil
}

func readRules(d *json.Decoder) ([]model.Rule, error) {
	if err := delimiter(d, '['); err != nil {
		return nil, err
	}
	rules := []model.Rule{}
	for d.More() {
		if len(rules) == model.MaxPolicyRules {
			return nil, fmt.Errorf("policy rules: %w", model.ErrLimitExceeded)
		}
		var r model.Rule
		err := readObject(d, []string{"path", "fields", "reason"}, func(key string) (err error) {
			switch key {
			case "path":
				r.Path, err = readString(d)
			case "reason":
				r.Reason, err = readString(d)
			case "fields":
				if err = delimiter(d, '['); err != nil {
					return err
				}
				r.Fields = []model.Field{}
				for d.More() {
					field, e := readString(d)
					if e != nil {
						return e
					}
					r.Fields = append(r.Fields, model.Field(field))
				}
				err = delimiter(d, ']')
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := delimiter(d, ']'); err != nil {
		return nil, err
	}
	return rules, nil
}

func delimiter(d *json.Decoder, want json.Delim) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t != want {
		return errors.New("invalid policy JSON shape")
	}
	return nil
}

func readString(d *json.Decoder) (string, error) {
	t, err := d.Token()
	if err != nil {
		return "", err
	}
	s, ok := t.(string)
	if !ok {
		return "", errors.New("policy member must be a string")
	}
	return s, nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject those
// escapes so a malformed path cannot silently become a different exact path.
// Syntax and ordinary escapes remain the JSON decoder's responsibility.
func validUnicodeEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' || i+1 >= len(data) {
			continue
		}
		if data[i+1] != 'u' || i+5 >= len(data) {
			i++
			continue
		}
		n, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+11 >= len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 5
	}
	return true
}
