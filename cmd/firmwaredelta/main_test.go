// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var binary, repo string

func TestMain(m *testing.M) {
	var err error
	repo, err = filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "firmwaredelta-process-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "firmwaredelta")
	// Cold trimpath toolchain builds can take minutes under full-system amd64
	// emulation. Runtime comparisons below retain their shorter deadlines.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		cancel()
		os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "actual CLI build failed: %v\n%s", err, out)
		os.Exit(2)
	}
	cancel()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func process(t *testing.T, args ...string) (int, []byte, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("CLI process failed: %v", err)
		}
	}
	if ctx.Err() != nil {
		t.Fatalf("CLI process timed out: %v", ctx.Err())
	}
	return code, stdout.Bytes(), stderr.String()
}

func TestRealCommandArgumentFailures(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"compare"}, {"compare", "--baseline=a", "--candidate=b", "--baseline=c"}, {"compare", "--baseline=a", "--candidate=b", "--format=xml"}} {
		code, stdout, stderr := process(t, args...)
		if code != 2 || len(stdout) != 0 || !strings.Contains(stderr, "firmwaredelta:") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := process(t, "--help")
	if code != 0 || len(stdout) != 0 || !strings.HasPrefix(stderr, "Usage:") {
		t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
