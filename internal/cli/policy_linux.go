// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// O_PATH anchors metadata without opening devices or FIFOs for I/O. Reopening
// the proven regular object through procfs preserves its identity across rename
// or symlink replacement. A policy symlink to a regular file is permitted.
func openPolicy(path string) (*os.File, error) {
	const pathOnly = 0x200000 // Linux O_PATH, absent from syscall's constants.
	fd, err := syscall.Open(path, pathOnly|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	anchor := os.NewFile(uintptr(fd), "policy metadata")
	defer anchor.Close()
	info, err := anchor.Stat()
	if err != nil {
		return nil, cause(err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("policy must be a regular file")
	}
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, cause(err)
	}
	return f, nil
}
