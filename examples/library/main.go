// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// The library example runs against the generated original demo by default.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	fd "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("library-example", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseline := flags.String("baseline", "dist/demo/baseline", "immutable baseline directory")
	candidate := flags.String("candidate", "dist/demo/candidate", "immutable candidate directory")
	policyPath := flags.String("policy", "dist/demo/policy.json", "policy file; empty allows nothing")
	format := flags.String("format", "markdown", "json or markdown")
	cancelNow := flags.Bool("cancel", false, "demonstrate cancellation before scanning")
	timeout := flags.Duration("timeout", 0, "optional comparison deadline, such as 5s")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*format != "json" && *format != "markdown") || *timeout < 0 {
		fmt.Fprintln(stderr, "use named flags, format json|markdown, and a nonnegative timeout")
		return 2
	}
	options := fd.Options{}
	if *policyPath != "" {
		f, err := os.Open(*policyPath)
		if err != nil {
			fmt.Fprintln(stderr, "open policy:", err)
			return 2
		}
		policy, readErr := fd.ReadPolicy(f)
		closeErr := f.Close()
		if readErr != nil {
			describe(stderr, readErr)
			return 2
		}
		if closeErr != nil {
			fmt.Fprintln(stderr, "close policy:", closeErr)
			return 2
		}
		options.Policy = &policy
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	if *cancelNow {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	report, err := fd.Compare(ctx, *baseline, *candidate, options)
	if err != nil {
		describe(stderr, err)
		return 2
	}
	// Both renderers consume the same validated report. Buffering here also keeps
	// this example's stdout empty if rendering fails before the final write.
	var jsonOutput, markdownOutput bytes.Buffer
	if err := fd.WriteJSON(&jsonOutput, report); err != nil {
		describe(stderr, err)
		return 2
	}
	if err := fd.WriteMarkdown(&markdownOutput, report); err != nil {
		describe(stderr, err)
		return 2
	}
	output := markdownOutput.Bytes()
	if *format == "json" {
		output = jsonOutput.Bytes()
	}
	if n, err := stdout.Write(output); err != nil || n != len(output) {
		if err == nil {
			err = io.ErrShortWrite
		}
		fmt.Fprintln(stderr, "write report:", err)
		return 2
	}
	// An embedding application decides how to handle report.Verdict. This example
	// exits zero after a completed comparison, even for unexpected_changes.
	return 0
}

func describe(w io.Writer, err error) {
	var input *fd.InputError
	var scan *fd.ScanError
	var policy *fd.PolicyError
	switch {
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(w, "comparison canceled")
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(w, "comparison deadline exceeded")
	case errors.As(err, &input):
		fmt.Fprintln(w, "input error:", input)
	case errors.As(err, &scan):
		fmt.Fprintln(w, "scan error:", scan)
	case errors.As(err, &policy):
		fmt.Fprintln(w, "policy error:", policy)
	default:
		fmt.Fprintln(w, "comparison/render error:", err)
	}
}
