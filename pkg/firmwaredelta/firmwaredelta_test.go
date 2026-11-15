// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package firmwaredelta_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	f "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func TestPublicPolicyAndRendering(t *testing.T) {
	p, err := f.ReadPolicy(strings.NewReader(`{"schema_version":1,"allow":[{"path":"usr/bin/tool","fields":["content"],"reason":"Approved rebuild"}]}`))
	if err != nil || len(p.Allow) != 1 || p.Allow[0].Fields[0] != f.FieldContent {
		t.Fatalf("public policy parse: %+v %v", p, err)
	}
	_, err = f.ReadPolicy(strings.NewReader(`{"schema_version":2,"allow":[]}`))
	var typed *f.PolicyError
	if !errors.As(err, &typed) {
		t.Fatalf("public PolicyError alias lost: %v", err)
	}
	_, err = f.ReadPolicy(strings.NewReader(strings.Repeat(" ", f.MaxPolicyBytes+1)))
	if !errors.Is(err, f.ErrLimitExceeded) {
		t.Fatalf("public limit sentinel lost: %v", err)
	}
	r := f.Report{SchemaVersion: f.SchemaVersion, BaselineDigest: strings.Repeat("a", 64), CandidateDigest: strings.Repeat("b", 64), Changes: []f.Change{{Path: "tool", Category: f.CategoryExecutable, Field: f.FieldMode, Before: f.StringValue("0755"), After: f.StringValue("4755")}}, Counts: f.Counts{Total: 1, Unexpected: 1}, Verdict: f.VerdictUnexpectedChanges}
	var out bytes.Buffer
	if err := f.WriteJSON(&out, r); err != nil || !strings.Contains(out.String(), `"unexpected":1`) {
		t.Fatalf("public JSON writer: %q %v", out.String(), err)
	}
	out.Reset()
	if err := f.WriteMarkdown(&out, r); err != nil || !strings.Contains(out.String(), "| tool | executable | mode |") {
		t.Fatalf("public Markdown writer: %q %v", out.String(), err)
	}
	sentinel := errors.New("deliberate sink failure")
	if err := f.WriteJSON(failedWriter{sentinel}, r); !errors.Is(err, sentinel) {
		t.Fatalf("JSON error not preserved: %v", err)
	}
	if err := f.WriteMarkdown(failedWriter{sentinel}, r); !errors.Is(err, sentinel) {
		t.Fatalf("Markdown error not preserved: %v", err)
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestContextAndConstructedPolicyErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer finish()
	for _, tc := range []struct {
		ctx   context.Context
		cause error
	}{{canceled, context.Canceled}, {expired, context.DeadlineExceeded}} {
		r, err := f.Compare(tc.ctx, "unopened-baseline", "unopened-candidate", f.Options{})
		var typed *f.ScanError
		if !errors.Is(err, tc.cause) || !errors.As(err, &typed) || !reflect.DeepEqual(r, f.Report{}) {
			t.Fatalf("context error/empty result lost: %+v %v", r, err)
		}
	}
	r, err := f.Compare(nil, "unopened-baseline", "unopened-candidate", f.Options{})
	var input *f.InputError
	if !errors.As(err, &input) || !reflect.DeepEqual(r, f.Report{}) {
		t.Fatalf("nil context: %+v %v", r, err)
	}
	for _, p := range []f.Policy{{}, {SchemaVersion: 2}, {SchemaVersion: 1, Allow: []f.Rule{{Path: "tool", Fields: []f.Field{f.FieldContent}, Reason: ""}}}} {
		r, err := f.Compare(context.Background(), "unopened-baseline", "unopened-candidate", f.Options{Policy: &p})
		var typed *f.PolicyError
		if !errors.As(err, &typed) || !reflect.DeepEqual(r, f.Report{}) {
			t.Fatalf("constructed policy did not fail before scan: %+v %v", r, err)
		}
	}
}

func TestExternalConsumerCompilesWithoutInternalImports(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	module := fmt.Sprintf("module external.example/consumer\n\ngo 1.27.0\n\nrequire github.com/firmdura/firmwaredelta v0.0.0\nreplace github.com/firmdura/firmwaredelta => %q\n", filepath.ToSlash(repo))
	program := `package main
import (
  "context"
  "errors"
  "io"
  "strings"
  f "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)
func main() {
  p, _ := f.ReadPolicy(strings.NewReader("{}"))
  p = f.Policy{SchemaVersion:f.SchemaVersion, Allow:[]f.Rule{{Path:"tool", Fields:[]f.Field{f.FieldContent}, Reason:"maintenance"}}}
  ctx, cancel := context.WithCancel(context.Background()); cancel()
  r, err := f.Compare(ctx, "baseline", "candidate", f.Options{Policy:&p})
  var input *f.InputError; var scan *f.ScanError; var policy *f.PolicyError
  _, _, _ = errors.As(err,&input), errors.As(err,&scan), errors.As(err,&policy)
  _, _, _ = errors.Is(err,f.ErrInputChanged), errors.Is(err,f.ErrLimitExceeded), errors.Is(err,f.ErrUnsupportedHost)
  _ = f.WriteJSON(io.Discard,r); _ = f.WriteMarkdown(io.Discard,r)
  size := int64(0); target := "literal"
  e := f.Entry{Path:"tool", Kind:f.KindFile, Mode:"0755", Category:f.CategoryExecutable, Size:&size, SHA256:strings.Repeat("a",64), ELF:&f.ELF{Class:"64",Endian:"little",Machine:62,Needed:[]string{}}}
  _ = f.Inventory{SchemaVersion:f.SchemaVersion, Entries:[]f.Entry{e}}
  _ = f.Change{Path:e.Path, Category:e.Category, Field:f.FieldPresence, Before:f.NullValue(), After:f.EntryValue(e)}
  _ = f.Report{Counts:f.Counts{}, Verdict:f.VerdictUnchanged, PolicyWarnings:[]f.Warning{{Path:"unused",Code:f.WarningUnusedRule}}}
  _ = []f.Value{f.ContentValue(f.Content{Size:0,SHA256:e.SHA256}),f.StringValue(target),f.MachineValue(62),f.NeededValue([]string{"libc.so.6"})}
  _ = []f.Kind{f.KindDirectory,f.KindSymlink,f.KindBlockDevice,f.KindCharDevice,f.KindFIFO,f.KindSocket}
  _ = []f.Category{f.CategoryConfig,f.CategoryLibrary,f.CategoryOther}
  _ = []f.Field{f.FieldKind,f.FieldMode,f.FieldTarget,f.FieldELFClass,f.FieldELFEndian,f.FieldELFMachine,f.FieldELFSONAME,f.FieldELFNeeded}
  _ = []f.Verdict{f.VerdictExpectedChanges,f.VerdictUnexpectedChanges}
  _ = []int{f.MaxEntries,f.MaxPathBytes,f.MaxPolicyBytes,f.MaxPolicyRules}
}
`
	for name, content := range map[string]string{"go.mod": module, "main.go": program} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-o", filepath.Join(dir, "consumer"), ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external consumer build failed: %v\n%s", err, out)
	}
}
