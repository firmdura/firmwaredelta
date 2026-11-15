// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"fmt"
)

var (
	ErrLimitExceeded   = errors.New("limit exceeded")
	ErrInputChanged    = errors.New("input changed during scan")
	ErrUnsupportedHost = errors.New("unsupported host: Linux amd64 required")
)

// InputError reports invalid arguments or unsupported execution conditions.
type InputError struct {
	Op  string
	Err error
}

func (e *InputError) Error() string { return fmt.Sprintf("input %s: %v", e.Op, e.Err) }
func (e *InputError) Unwrap() error { return e.Err }

// ScanError reports unavailable filesystem evidence. Path is root-relative;
// an empty Path denotes the root. Err must not include file contents.
type ScanError struct {
	Op   string
	Path string
	Err  error
}

func (e *ScanError) Error() string { return fmt.Sprintf("scan %s %q: %v", e.Op, e.Path, e.Err) }
func (e *ScanError) Unwrap() error { return e.Err }

// PolicyError reports malformed, unsupported or invalid policy evidence.
type PolicyError struct {
	Op  string
	Err error
}

func (e *PolicyError) Error() string { return fmt.Sprintf("policy %s: %v", e.Op, e.Err) }
func (e *PolicyError) Unwrap() error { return e.Err }
