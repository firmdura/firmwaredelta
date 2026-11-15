// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package render writes validated reports without reading files or changing
// comparison facts or policy decisions. Both formats normalize independent
// copies before producing output. Markdown displays metadata values as escaped
// JSON, preserving distinctions such as null, empty strings and empty arrays.
package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/firmdura/firmwaredelta/internal/model"
)

// WriteJSON writes compact schema-1 JSON followed by one newline. Invalid
// reports produce no output. Validation, encoding and writer errors propagate.
func WriteJSON(w io.Writer, report model.Report) error {
	normal, err := model.NormalizeReport(report)
	if err != nil {
		return err
	}
	data, err := json.Marshal(normal)
	if err != nil {
		return err
	}
	return write(w, append(data, '\n'))
}

// WriteMarkdown writes all report facts, decisions, rationales and warnings.
// Caller text cannot create Markdown structure, HTML, links or terminal control
// sequences. Invalid reports produce no output. Writer errors propagate.
func WriteMarkdown(w io.Writer, report model.Report) error {
	normal, err := model.NormalizeReport(report)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "# FirmwareDelta report\n\nSchema version: %d\n\nBaseline inventory digest: %s\n\nCandidate inventory digest: %s\n\nVerdict: %s\n\nChanges: total=%d; expected=%d; unexpected=%d\n\n## Changes\n\n",
		normal.SchemaVersion, escapeMarkdown(normal.BaselineDigest), escapeMarkdown(normal.CandidateDigest),
		escapeMarkdown(string(normal.Verdict)), normal.Counts.Total, normal.Counts.Expected, normal.Counts.Unexpected)
	if len(normal.Changes) == 0 {
		out.WriteString("No changes.\n")
	} else {
		out.WriteString("| Path | Category | Field | Before | After | Expected | Rationale |\n| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, c := range normal.Changes {
			before, err := c.Before.MarshalJSON()
			if err != nil {
				return err
			}
			after, err := c.After.MarshalJSON()
			if err != nil {
				return err
			}
			fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %t | %s |\n",
				escapeMarkdown(c.Path), escapeMarkdown(string(c.Category)), escapeMarkdown(string(c.Field)),
				escapeMarkdown(string(before)), escapeMarkdown(string(after)), c.Expected, escapeMarkdown(c.Reason))
		}
	}
	out.WriteString("\n## Policy warnings\n\n")
	if len(normal.PolicyWarnings) == 0 {
		out.WriteString("No policy warnings.\n")
	} else {
		out.WriteString("| Path | Code |\n| --- | --- |\n")
		for _, warning := range normal.PolicyWarnings {
			fmt.Fprintf(&out, "| %s | %s |\n", escapeMarkdown(warning.Path), escapeMarkdown(string(warning.Code)))
		}
	}
	return write(w, out.Bytes())
}

// Entities are parsed as text by Markdown, rather than reinterpreted as syntax.
// Escaping URL and email punctuation also prevents GFM's automatic links.
// Controls and Unicode formatting/line separators use visible Unicode escapes.
func escapeMarkdown(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			if r <= 0xffff {
				fmt.Fprintf(&out, "&#92;u%04x", r)
			} else {
				fmt.Fprintf(&out, "&#92;U%08x", r)
			}
		case strings.ContainsRune("\\`*_{}[]()<>#+-.!|&\"':@~$^=", r):
			fmt.Fprintf(&out, "&#%d;", r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func write(w io.Writer, data []byte) error {
	if w == nil {
		return errors.New("nil report writer")
	}
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
