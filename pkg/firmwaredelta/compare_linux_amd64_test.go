// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package firmwaredelta_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	f "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func put(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func state(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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

func TestCompareOutcomesAndInputImmutability(t *testing.T) {
	base, candidate := t.TempDir(), t.TempDir()
	const secret = "SENTINEL_PRIVATE_CONFIGURATION_VALUE_095287"
	for _, root := range []string{base, candidate} {
		put(t, filepath.Join(root, "usr/bin/tool"), "original synthetic executable bytes\n", 0755)
		put(t, filepath.Join(root, "etc/private.conf"), secret, 0644)
		if err := os.Symlink("/outside/literal", filepath.Join(root, "external-link")); err != nil {
			t.Fatal(err)
		}
	}
	r, err := f.Compare(context.Background(), base, candidate, f.Options{})
	if err != nil || r.Verdict != f.VerdictUnchanged {
		t.Fatalf("identical: %+v %v", r, err)
	}
	put(t, filepath.Join(candidate, "usr/bin/tool"), "rebuilt synthetic executable bytes\n", 0644)
	put(t, filepath.Join(candidate, "etc/private.conf"), secret+" changed", 0644)
	beforeBase, beforeCandidate := state(t, base), state(t, candidate)
	p := f.Policy{SchemaVersion: 1, Allow: []f.Rule{{Path: "usr/bin/tool", Fields: []f.Field{f.FieldContent}, Reason: "Approved maintenance rebuild"}}}
	r, err = f.Compare(context.Background(), base, candidate, f.Options{Policy: &p})
	if err != nil || r.Counts != (f.Counts{Total: 3, Expected: 1, Unexpected: 2}) || r.Verdict != f.VerdictUnexpectedChanges {
		t.Fatalf("narrow policy suppressed unrelated changes: %+v %v", r, err)
	}
	if r.Changes[0].Path != "etc/private.conf" || r.Changes[0].Expected || r.Changes[2].Field != f.FieldMode || r.Changes[2].Expected {
		t.Fatalf("wrong changes/decisions: %+v", r.Changes)
	}
	var first, second bytes.Buffer
	if err := f.WriteJSON(&first, r); err != nil {
		t.Fatal(err)
	}
	repeat, err := f.Compare(context.Background(), base, candidate, f.Options{Policy: &p})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WriteJSON(&second, repeat); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("repeat changed canonical report: %v", err)
	}
	if strings.Contains(first.String(), secret) || strings.Contains(first.String(), base) || strings.Contains(first.String(), candidate) {
		t.Fatal("report leaked contents or host paths")
	}
	p.Allow[0].Fields = append(p.Allow[0].Fields, f.FieldMode)
	p.Allow = append(p.Allow, f.Rule{Path: "etc/private.conf", Fields: []f.Field{f.FieldContent}, Reason: "Approved configuration edit"})
	r, err = f.Compare(context.Background(), base, candidate, f.Options{Policy: &p})
	if err != nil || r.Verdict != f.VerdictExpectedChanges || r.Counts.Expected != 3 {
		t.Fatalf("expected-only: %+v %v", r, err)
	}
	if !reflect.DeepEqual(beforeBase, state(t, base)) || !reflect.DeepEqual(beforeCandidate, state(t, candidate)) {
		t.Fatal("comparison wrote input bytes/modes/link targets")
	}
}

func TestCompareTypedInputAndScanFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("unreadability evidence requires an unprivileged Linux user")
	}
	base := t.TempDir()
	for _, tc := range []struct {
		name  string
		setup func(string) string
		input bool
	}{
		{"missing", func(root string) string { return filepath.Join(root, "missing") }, false},
		{"symlink root", func(root string) string {
			link := filepath.Join(root, "link")
			if err := os.Symlink(base, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, true},
		{"file root", func(root string) string {
			path := filepath.Join(root, "file")
			put(t, path, "ordinary", 0644)
			return path
		}, true},
		{"malformed ELF", func(root string) string {
			put(t, filepath.Join(root, "broken"), "\x7fELF_PRIVATE_CONTENT_MUST_NOT_LEAK", 0644)
			return root
		}, false},
		{"unreadable file", func(root string) string {
			path := filepath.Join(root, "unreadable")
			put(t, path, "PRIVATE_CONTENT_MUST_NOT_LEAK", 0000)
			t.Cleanup(func() { _ = os.Chmod(path, 0600) })
			return root
		}, false},
		{"unreadable root", func(root string) string {
			if err := os.Chmod(root, 0000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(root, 0700) })
			return root
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.setup(t.TempDir())
			r, err := f.Compare(context.Background(), base, root, f.Options{})
			var input *f.InputError
			var scan *f.ScanError
			if err == nil || !reflect.DeepEqual(r, f.Report{}) || tc.input && !errors.As(err, &input) || !tc.input && !errors.As(err, &scan) {
				t.Fatalf("wrong typed failure/partial report: %+v %v", r, err)
			}
			if strings.Contains(err.Error(), "PRIVATE_CONTENT_MUST_NOT_LEAK") || strings.Contains(err.Error(), root) {
				t.Fatalf("scan error leaked input evidence: %v", err)
			}
		})
	}
}

func TestCompareCancellationDuringScan(t *testing.T) {
	base, candidate := t.TempDir(), t.TempDir()
	file, err := os.Create(filepath.Join(base, "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(256 << 20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(time.Millisecond); cancel() }()
	start := time.Now()
	r, err := f.Compare(ctx, base, candidate, f.Options{})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(r, f.Report{}) || time.Since(start) > 5*time.Second {
		t.Fatalf("scan cancellation did not propagate promptly: %+v %v", r, err)
	}
}
