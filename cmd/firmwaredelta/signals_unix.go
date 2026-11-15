// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func ignoreBrokenPipe() { signal.Ignore(syscall.SIGPIPE) }

func terminationSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
