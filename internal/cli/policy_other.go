// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

import (
	"errors"
	"os"
)

// Compare rejects unsupported hosts; ordinary policy parsing remains usable.
func openPolicy(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, cause(err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("policy must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, cause(err)
	}
	return f, nil
}
