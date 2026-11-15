// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	f "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(repo, "testdata/cli", name)
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if filepath.ToSlash(rel) == "usr/bin/tool" {
			mode = 0755
		}
		return os.WriteFile(dest, data, mode)
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func inputState(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		value := fmt.Sprint(info.Mode())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(data))
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += ":" + target
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[rel] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func libraryJSON(t *testing.T, base, candidate, policyPath string) []byte {
	t.Helper()
	var options f.Options
	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := f.ReadPolicy(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		options.Policy = &policy
	}
	r, err := f.Compare(context.Background(), base, candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := f.WriteJSON(&out, r); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestRealProcessComparisonsGoldensAndImmutability(t *testing.T) {
	base, candidate := copyFixture(t, "baseline"), copyFixture(t, "candidate")
	policy := filepath.Join(repo, "testdata/cli/policy.json")
	beforeBase, beforeCandidate, beforePolicy := inputState(t, base), inputState(t, candidate), inputState(t, policy)
	allPolicy := filepath.Join(t.TempDir(), "all.json")
	if err := os.WriteFile(allPolicy, []byte(`{"schema_version":1,"allow":[{"path":"usr/bin/tool","fields":["content"],"reason":"Approved rebuild"},{"path":"etc/service.conf","fields":["content"],"reason":"Approved setting change"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, after, policy string
		code, expected      int
		verdict             f.Verdict
	}{
		{"identical", base, "", 0, 0, f.VerdictUnchanged},
		{"unexpected", candidate, "", 1, 0, f.VerdictUnexpectedChanges},
		{"narrow policy", candidate, policy, 1, 1, f.VerdictUnexpectedChanges},
		{"expected only", candidate, allPolicy, 0, 2, f.VerdictExpectedChanges},
		{"unused policy with unchanged roots", base, policy, 0, 0, f.VerdictUnchanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"compare", "--baseline=" + base, "--candidate=" + tc.after, "--format=json"}
			if tc.policy != "" {
				args = append(args, "--policy", tc.policy)
			}
			code, stdout, stderr := process(t, args...)
			if code != tc.code || stderr != "" {
				t.Fatalf("code=%d stderr=%q", code, stderr)
			}
			var report f.Report
			if err := json.Unmarshal(stdout, &report); err != nil || report.Validate() != nil || report.Verdict != tc.verdict || report.Counts.Expected != tc.expected {
				t.Fatalf("wrong actual report: %+v %v", report, err)
			}
			if !bytes.Equal(stdout, libraryJSON(t, base, tc.after, tc.policy)) {
				t.Fatal("CLI and public library reports disagree")
			}
			if strings.Contains(string(stdout), "original_setting=1") || strings.Contains(string(stdout), "unexpected_setting=2") || strings.Contains(string(stdout), base) || strings.Contains(string(stdout), candidate) {
				t.Fatal("CLI leaked input contents or host roots")
			}
		})
	}
	for _, format := range []string{"json", "markdown", "default"} {
		args := []string{"compare", "--baseline", base, "--candidate", candidate, "--policy", policy}
		if format != "default" {
			args = append(args, "--format", format)
		}
		code, stdout, stderr := process(t, args...)
		if code != 1 || stderr != "" {
			t.Fatalf("golden %s code=%d stderr=%q", format, code, stderr)
		}
		ext := "md"
		if format == "json" {
			ext = "json"
		}
		want, err := os.ReadFile(filepath.Join(repo, "testdata/cli/compare."+ext+".golden"))
		if err != nil || !bytes.Equal(stdout, want) {
			t.Fatalf("real CLI %s golden mismatch: %v\n%s", format, err, stdout)
		}
		_, repeated, _ := process(t, args...)
		if !bytes.Equal(stdout, repeated) {
			t.Fatalf("real CLI %s is not byte-identical on repeat", format)
		}
	}
	if !reflect.DeepEqual(beforeBase, inputState(t, base)) || !reflect.DeepEqual(beforeCandidate, inputState(t, candidate)) || !reflect.DeepEqual(beforePolicy, inputState(t, policy)) {
		t.Fatal("CLI/library modified root bytes, modes or policy")
	}
}

func TestRealProcessComparesCheckedInRoots(t *testing.T) {
	// The documented Linux wrapper mounts this source tree read-only. Compare
	// the actual checked-in roots as well as the mutable copies above.
	base := filepath.Join(repo, "testdata/cli/baseline")
	candidate := filepath.Join(repo, "testdata/cli/candidate")
	policy := filepath.Join(repo, "testdata/cli/policy.json")
	beforeBase, beforeCandidate := inputState(t, base), inputState(t, candidate)
	code, stdout, stderr := process(t, "compare", "--baseline", base, "--candidate", candidate, "--policy", policy, "--format", "json")
	var report f.Report
	if err := json.Unmarshal(stdout, &report); err != nil || code != 1 || stderr != "" || report.Counts != (f.Counts{Total: 2, Expected: 1, Unexpected: 1}) {
		t.Fatalf("source-root comparison: code=%d report=%+v stderr=%q err=%v", code, report, stderr, err)
	}
	if !bytes.Equal(stdout, libraryJSON(t, base, candidate, policy)) || !reflect.DeepEqual(beforeBase, inputState(t, base)) || !reflect.DeepEqual(beforeCandidate, inputState(t, candidate)) {
		t.Fatal("source-root library/CLI mismatch or input modification")
	}
}

func TestRealProcessInvalidEvidenceHasNoReport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("process unreadability checks require an unprivileged Linux user")
	}
	base := copyFixture(t, "baseline")
	for _, name := range []string{"bad policy", "malformed ELF", "unreadable root", "unreadable file", "symlink root", "missing root", "baseline failure", "policy FIFO"} {
		t.Run(name, func(t *testing.T) {
			candidate := copyFixture(t, "candidate")
			before := base
			var extra []string
			switch name {
			case "bad policy":
				path := filepath.Join(t.TempDir(), "policy.json")
				if err := os.WriteFile(path, []byte(`{"schema_version":1,"allow":[{"path":"usr/bin/tool","fields":["unknown"],"reason":"bad"}]}`), 0644); err != nil {
					t.Fatal(err)
				}
				extra = []string{"--policy", path}
			case "malformed ELF":
				if err := os.WriteFile(filepath.Join(candidate, "broken"), []byte("\x7fELFPRIVATE_SENTINEL_MUST_NOT_LEAK"), 0644); err != nil {
					t.Fatal(err)
				}
			case "unreadable root":
				if err := os.Chmod(candidate, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(candidate, 0755) })
			case "unreadable file":
				path := filepath.Join(candidate, "etc/service.conf")
				if err := os.Chmod(path, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0644) })
			case "symlink root":
				link := filepath.Join(t.TempDir(), "root-link")
				if err := os.Symlink(candidate, link); err != nil {
					t.Fatal(err)
				}
				candidate = link
			case "missing root":
				candidate = filepath.Join(candidate, "not-present")
			case "baseline failure":
				before = filepath.Join(base, "not-present")
			case "policy FIFO":
				path := filepath.Join(t.TempDir(), "fifo")
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				extra = []string{"--policy", path}
			}
			args := append([]string{"compare", "--baseline", before, "--candidate", candidate, "--format", "json"}, extra...)
			code, stdout, stderr := process(t, args...)
			if code != 2 || len(stdout) != 0 || stderr == "" || strings.Contains(stderr, "PRIVATE_SENTINEL_MUST_NOT_LEAK") || strings.Contains(stderr, "unexpected_setting=2") {
				t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
			}
		})
	}
}

func TestRealProcessNarrowPolicyDoesNotAllowMode(t *testing.T) {
	base, candidate := copyFixture(t, "baseline"), copyFixture(t, "candidate")
	if err := os.Chmod(filepath.Join(candidate, "usr/bin/tool"), 0644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := process(t, "compare", "--baseline", base, "--candidate", candidate, "--format", "json", "--policy", filepath.Join(repo, "testdata/cli/policy.json"))
	var report f.Report
	if err := json.Unmarshal(stdout, &report); err != nil || code != 1 || stderr != "" || report.Counts != (f.Counts{Total: 3, Expected: 1, Unexpected: 2}) {
		t.Fatalf("mode decision lost: code=%d report=%+v stderr=%q err=%v", code, report, stderr, err)
	}
	for _, change := range report.Changes {
		if change.Field == f.FieldMode && change.Expected {
			t.Fatal("content-only policy allowed mode")
		}
	}
}

func TestRealProcessWriterFailuresExitTwo(t *testing.T) {
	root := t.TempDir()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	defer writer.Close()
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	for _, sink := range []*os.File{writer, full} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, binary, "compare", "--baseline", root, "--candidate", root, "--format", "json")
		var stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = sink, &stderr
		err := cmd.Run()
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || !strings.Contains(stderr.String(), "write report") {
			t.Fatalf("real output failure did not exit2: error=%v stderr=%q", err, stderr.String())
		}
	}
}

func TestRealELFDependencyChangeReachesProcessReport(t *testing.T) {
	fixture := filepath.Join(repo, "dist/cli-elf-fixtures")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "bash", filepath.Join(repo, "testdata/elf-src/build.sh"), fixture)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("mandatory real ELF fixture compile/readelf failed: %v\n%s", err, out)
	}
	base, candidate := filepath.Join(fixture, "baseline"), filepath.Join(fixture, "candidate")
	beforeBase, beforeCandidate := inputState(t, base), inputState(t, candidate)
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"schema_version":1,"allow":[{"path":"usr/bin/maintenance","fields":["content"],"reason":"Approved rebuild only"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := process(t, "compare", "--baseline", base, "--candidate", candidate, "--policy", policy, "--format", "json")
	var report f.Report
	if err := json.Unmarshal(stdout, &report); err != nil || code != 1 || stderr != "" {
		t.Fatalf("real ELF process: code=%d stderr=%q err=%v", code, stderr, err)
	}
	found := false
	for _, change := range report.Changes {
		if change.Path == "usr/bin/maintenance" && change.Field == f.FieldELFNeeded {
			found = true
			if change.Expected || change.Before.Needed == nil || change.After.Needed == nil || slices.Contains(*change.Before.Needed, "libextra.so.1") || !slices.Contains(*change.After.Needed, "libextra.so.1") {
				t.Fatalf("dependency fact lost/allowed: %+v", change)
			}
		}
	}
	if !found || !bytes.Equal(stdout, libraryJSON(t, base, candidate, policy)) {
		t.Fatal("real dependency evidence missing or CLI/library mismatch")
	}
	if !reflect.DeepEqual(beforeBase, inputState(t, base)) || !reflect.DeepEqual(beforeCandidate, inputState(t, candidate)) {
		t.Fatal("real ELF inputs were modified")
	}
}
