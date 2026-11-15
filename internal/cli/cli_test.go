// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firmdura/firmwaredelta/internal/cli"
)

func TestInvalidArgumentsNeverProduceReport(t *testing.T) {
	for _, args := range [][]string{
		nil, {"other"}, {"compare"}, {"compare", "--baseline", "a"},
		{"compare", "--baseline", "a", "--candidate"},
		{"compare", "--baseline", "--candidate", "b"},
		{"compare", "--baseline=", "--candidate=b"},
		{"compare", "--baseline=a", "--candidate=b", "--policy="},
		{"compare", "--baseline=a", "--candidate=b", "--format=JSON"},
		{"compare", "--baseline=a", "--candidate=b", "--format=xml"},
		{"compare", "--baseline=a", "--candidate=b", "--format="},
		{"compare", "--baseline=a", "--candidate=b", "--baseline=a"},
		{"compare", "--baseline=a", "--candidate=b", "--candidate=c"},
		{"compare", "--baseline=a", "--candidate=b", "--policy=p", "--policy=q"},
		{"compare", "--baseline=a", "--candidate=b", "--format=json", "--format=markdown"},
		{"compare", "--baseline=a", "--candidate=b", "--unknown=x"},
		{"compare", "--baseline=a", "--candidate=b", "extra"},
		{"compare", "--baseline=a", "--candidate=b", "--"},
		{"compare", "--baseline=a", "--candidate=b", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestHelpAndDiagnosticStreams(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"compare", "--help"}, {"compare", "-h"}} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(context.Background(), args, &stdout, &stderr); code != 0 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "Usage:") {
			t.Fatalf("help: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"compare", "\x1b[31m"}, &stdout, &stderr); code != 2 || bytes.ContainsRune(stderr.Bytes(), '\x1b') {
		t.Fatalf("raw control in argument diagnostic: code=%d stderr=%q", code, stderr.String())
	}
	if code := cli.Run(context.Background(), []string{"compare"}, nil, nil); code != 2 {
		t.Fatalf("nil diagnostic sink code=%d", code)
	}
}

func TestPolicyFailureBeforeAnyOutput(t *testing.T) {
	root := t.TempDir()
	for _, data := range []string{`{"schema_version":2,"allow":[]}`, `{"schema_version":1,"schema_version":1,"allow":[]}`, "not JSON"} {
		path := filepath.Join(root, "policy.json")
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		args := []string{"compare", "--baseline", "unopened-baseline", "--candidate", "unopened-candidate", "--policy", path}
		if code := cli.Run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "policy") || strings.Contains(stderr.String(), root) {
			t.Fatalf("bad policy: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func TestContextFailureDoesNotWriteReport(t *testing.T) {
	for _, ctx := range []context.Context{nil, canceledContext()} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(ctx, []string{"compare", "--baseline=a", "--candidate=b"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("context: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
