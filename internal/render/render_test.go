// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/firmdura/firmwaredelta/internal/model"
	"github.com/firmdura/firmwaredelta/internal/render"
)

var formats = []struct {
	name  string
	write func(io.Writer, model.Report) error
}{{"json", render.WriteJSON}, {"md", render.WriteMarkdown}}

func load(t *testing.T, name string) model.Report {
	t.Helper()
	data, err := os.ReadFile("../../testdata/render/" + name + ".input.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func encode(t *testing.T, write func(io.Writer, model.Report) error, r model.Report) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := write(&out, r); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGoldenReportsAndJSONRoundTrip(t *testing.T) {
	for _, name := range []string{"unchanged", "expected", "unexpected"} {
		t.Run(name, func(t *testing.T) {
			r := load(t, name)
			before := jsonBytes(t, r)
			normal, err := model.NormalizeReport(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, format := range formats {
				out := encode(t, format.write, r)
				path := "../../testdata/render/" + name + "." + format.name + ".golden"
				if os.Getenv("UPDATE_RENDER_GOLDEN") == "1" {
					if err := os.WriteFile(path, out, 0644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, want) {
					t.Fatalf("%s golden mismatch:\n%s", format.name, out)
				}
				if !bytes.Equal(out, encode(t, format.write, r)) {
					t.Fatalf("%s rendering is not repeatable", format.name)
				}
				shuffled := r
				shuffled.Changes = slices.Clone(r.Changes)
				shuffled.PolicyWarnings = slices.Clone(r.PolicyWarnings)
				slices.Reverse(shuffled.Changes)
				slices.Reverse(shuffled.PolicyWarnings)
				if !bytes.Equal(out, encode(t, format.write, shuffled)) {
					t.Fatalf("%s rendering depends on input order", format.name)
				}
				if format.name == "json" {
					if len(out) < 2 || out[len(out)-1] != '\n' || bytes.Count(out, []byte{'\n'}) != 1 {
						t.Fatal("JSON must be compact with exactly one trailing newline")
					}
					var decoded model.Report
					if err := json.Unmarshal(out, &decoded); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(normal, decoded) {
						t.Fatalf("JSON lost facts or decisions:\n%+v\n%+v", normal, decoded)
					}
					if !bytes.Equal(out, append(jsonBytes(t, normal), '\n')) {
						t.Fatal("JSON differs from the normalized wire contract")
					}
				} else {
					assertMarkdownFacts(t, string(out), normal)
				}
			}
			if !bytes.Equal(before, jsonBytes(t, r)) {
				t.Fatal("renderer mutated caller report")
			}
		})
	}
}

func assertMarkdownFacts(t *testing.T, out string, report model.Report) {
	t.Helper()
	var rows [][]string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 9 || parts[1] == " Path " || parts[1] == " --- " {
			continue
		}
		row := make([]string, 7)
		for i := range row {
			row[i] = html.UnescapeString(strings.TrimSpace(parts[i+1]))
		}
		rows = append(rows, row)
	}
	if len(rows) != len(report.Changes) {
		t.Fatalf("Markdown shows %d records, want %d", len(rows), len(report.Changes))
	}
	for i, c := range report.Changes {
		want := []string{c.Path, string(c.Category), string(c.Field), string(jsonBytes(t, c.Before)), string(jsonBytes(t, c.After)), "false", c.Reason}
		if c.Expected {
			want[5] = "true"
		}
		if !slices.Equal(rows[i], want) {
			t.Fatalf("Markdown lost structured fact: got %#v, want %#v", rows[i], want)
		}
	}
	decoded := html.UnescapeString(out)
	for _, w := range report.PolicyWarnings {
		if !strings.Contains(decoded, "| "+w.Path+" | "+string(w.Code)+" |") {
			t.Fatalf("Markdown omitted warning: %+v", w)
		}
	}
}

func TestMarkdownCallerTextIsInert(t *testing.T) {
	payload := "|`*_[label](https://example.com) <img src=x onerror='boom'> &lt;script&gt; www.example.com me@example.com @user #123 ~strike~ $math$ \\\n\r\t\x1b[31m\x7f\u0085\u202e\u2028\u2029"
	pathPayload := strings.ReplaceAll(payload, "/", "∕")
	path := "etc/" + pathPayload
	size := int64(1)
	file := model.Entry{Path: "usr/lib/untrusted", Kind: model.KindFile, Category: model.CategoryLibrary, Mode: "0644", Size: &size, SHA256: strings.Repeat("c", 64), ELF: &model.ELF{Class: "64", Endian: "little", Machine: 62, SONAME: payload, Needed: []string{payload}}}
	link := model.Entry{Path: "link", Kind: model.KindSymlink, Category: model.CategoryOther, Mode: "0777", Target: &payload}
	r := model.Report{SchemaVersion: 1, BaselineDigest: strings.Repeat("a", 64), CandidateDigest: strings.Repeat("b", 64), Changes: []model.Change{
		{Path: path, Category: model.CategoryConfig, Field: model.FieldMode, Before: model.StringValue("0644"), After: model.StringValue("0600"), Expected: true, Reason: payload},
		{Path: file.Path, Category: file.Category, Field: model.FieldPresence, After: model.EntryValue(file)},
		{Path: link.Path, Category: link.Category, Field: model.FieldPresence, After: model.EntryValue(link)},
	}, PolicyWarnings: []model.Warning{{Path: "unused/" + pathPayload, Code: model.WarningUnusedRule}}, Counts: model.Counts{Total: 3, Expected: 1, Unexpected: 2}, Verdict: model.VerdictUnexpectedChanges}
	out := string(encode(t, render.WriteMarkdown, r))
	for _, dangerous := range []string{"<img", "&lt;script", "https://", "www.example.com", "me@example.com", "@user", " #123", "[label]", "`", "~strike~", "$math$"} {
		if strings.Contains(out, dangerous) {
			t.Fatalf("active caller text in Markdown: %q", dangerous)
		}
	}
	for _, runeValue := range out {
		if runeValue != '\n' && (unicode.IsControl(runeValue) || unicode.Is(unicode.Cf, runeValue) || unicode.Is(unicode.Zl, runeValue) || unicode.Is(unicode.Zp, runeValue)) {
			t.Fatalf("raw terminal/formatting control U+%04X", runeValue)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| ") {
			if count := strings.Count(line, "|"); count != 8 && count != 3 {
				t.Fatalf("caller text changed table structure: %q", line)
			}
		}
	}
	// One entity decode produces literal text, including the original entity
	// spelling; it cannot turn the caller's &lt;script&gt; into a tag.
	decoded := html.UnescapeString(out)
	if !strings.Contains(decoded, "&lt;script&gt;") || !strings.Contains(out, "&#92;u001b") || !strings.Contains(out, "&#92;u202e") {
		t.Fatal("caller text was lost rather than visibly escaped")
	}
	jsonOut := encode(t, render.WriteJSON, r)
	if bytes.ContainsRune(jsonOut, '\x1b') {
		t.Fatal("raw ANSI escape in JSON")
	}
	var roundTrip model.Report
	if err := json.Unmarshal(jsonOut, &roundTrip); err != nil || roundTrip.Changes[0].Reason != payload {
		t.Fatalf("JSON lost caller text: %v", err)
	}
}

func TestNoFileContentInReports(t *testing.T) {
	secret := []byte("DO_NOT_DISCLOSE_PRIVATE_CONFIGURATION_VALUE_6e7442")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "private.conf"), secret, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(secret)
	r := load(t, "expected")
	r.Changes[0].Path, r.Changes[0].Category, r.Changes[0].Field = "etc/private.conf", model.CategoryConfig, model.FieldContent
	r.Changes[0].Before = model.ContentValue(model.Content{Size: 0, SHA256: strings.Repeat("c", 64)})
	r.Changes[0].After = model.ContentValue(model.Content{Size: int64(len(secret)), SHA256: hex.EncodeToString(sum[:])})
	for _, format := range formats {
		out := encode(t, format.write, r)
		if bytes.Contains(out, secret) || bytes.Contains(out, []byte(dir)) {
			t.Fatalf("%s leaked file content or host path", format.name)
		}
		if !bytes.Contains(out, []byte(hex.EncodeToString(sum[:]))) {
			t.Fatalf("%s lost content hash", format.name)
		}
	}
}

type spyWriter struct{ calls int }

func (s *spyWriter) Write(p []byte) (int, error) { s.calls++; return len(p), nil }

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type partialWriter struct{ err error }

func (w partialWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

func TestInvalidReportProducesNoOutput(t *testing.T) {
	for _, corrupt := range []func(*model.Report){
		func(r *model.Report) { r.SchemaVersion = 2 },
		func(r *model.Report) { r.Counts.Expected++ },
		func(r *model.Report) { r.Verdict = model.VerdictUnchanged },
		func(r *model.Report) { r.Changes[0].Reason = "" },
		func(r *model.Report) { r.Changes[0].After.Machine = new(uint16) },
		func(r *model.Report) { r.PolicyWarnings = []model.Warning{{Path: "bad", Code: "unrecognized"}} },
	} {
		for _, format := range formats {
			r := load(t, "expected")
			corrupt(&r)
			var out spyWriter
			if err := format.write(&out, r); err == nil || out.calls != 0 {
				t.Fatalf("%s wrote an invalid report: error=%v calls=%d", format.name, err, out.calls)
			}
		}
	}
}

func TestWriterFailures(t *testing.T) {
	sentinel := errors.New("deliberate writer failure")
	r := load(t, "unexpected")
	for _, format := range formats {
		for _, writer := range []io.Writer{failingWriter{sentinel}, partialWriter{sentinel}} {
			if err := format.write(writer, r); !errors.Is(err, sentinel) {
				t.Fatalf("%s lost writer error: %v", format.name, err)
			}
		}
		if err := format.write(partialWriter{}, r); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("%s ignored short write: %v", format.name, err)
		}
		if err := format.write(nil, r); err == nil {
			t.Fatalf("%s ignored nil writer", format.name)
		}
	}
}
