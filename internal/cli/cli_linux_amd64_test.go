// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/firmwaredelta/internal/cli"
)

type badWriter struct{ partial bool }

func (w badWriter) Write(p []byte) (int, error) {
	if w.partial {
		return len(p) / 2, nil
	}
	return 0, errors.New("deliberate output failure")
}

func TestReportWriterFailuresAreExitTwo(t *testing.T) {
	root := t.TempDir()
	for _, sink := range []io.Writer{nil, badWriter{}, badWriter{partial: true}} {
		for _, format := range []string{"json", "markdown"} {
			var stderr bytes.Buffer
			code := cli.Run(context.Background(), []string{"compare", "--baseline", root, "--candidate", root, "--format", format}, sink, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "write report") {
				t.Fatalf("writer failure code=%d stderr=%q", code, stderr.String())
			}
		}
	}
}

func TestPolicySpecialFilesDoNotBlock(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{fifo, "/dev/zero", root} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var stdout, stderr bytes.Buffer
		start := time.Now()
		code := cli.Run(ctx, []string{"compare", "--baseline", root, "--candidate", root, "--policy", policy}, &stdout, &stderr)
		cancel()
		if code != 2 || stdout.Len() != 0 || time.Since(start) > time.Second || !strings.Contains(stderr.String(), "regular file") {
			t.Fatalf("special policy=%q code=%d stdout=%q stderr=%q", policy, code, stdout.String(), stderr.String())
		}
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"allow":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "policy-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"compare", "--baseline", root, "--candidate", root, "--policy", link}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("regular symlinked policy failed: code=%d stderr=%q", code, stderr.String())
	}
}
