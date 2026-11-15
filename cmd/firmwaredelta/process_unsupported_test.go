// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package main

import (
	"strings"
	"testing"
)

func TestRealCompareRejectsUnsupportedHost(t *testing.T) {
	code, stdout, stderr := process(t, "compare", "--baseline", ".", "--candidate", ".", "--format", "json")
	if code != 2 || len(stdout) != 0 || !strings.Contains(stderr, "unsupported host: Linux amd64 required") {
		t.Fatalf("unsupported compare code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
