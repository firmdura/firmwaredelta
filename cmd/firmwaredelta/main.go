// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/firmdura/firmwaredelta/internal/cli"
)

func main() {
	ignoreBrokenPipe()
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
