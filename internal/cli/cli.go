// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package cli maps validated public-library results to command output and exits.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

const usage = "Usage: firmwaredelta compare --baseline OLD_ROOT --candidate NEW_ROOT [--policy policy.json] [--format json|markdown]\n"

type arguments struct {
	baseline, candidate, policy, format string
}

// Run returns 0 for unchanged/expected-only results, 1 for unexpected changes,
// and 2 for invalid arguments, missing evidence, cancellation or output failure.
// Reports reach stdout only after complete comparison and rendering. Diagnostics
// and help go to stderr; Run never exits the process.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") || len(args) == 2 && args[0] == "compare" && (args[1] == "--help" || args[1] == "-h") {
		if err := write(stderr, []byte(usage)); err != nil {
			return 2
		}
		return 0
	}
	flags, err := parse(args)
	if err != nil {
		return fail(stderr, err)
	}
	var options firmwaredelta.Options
	if flags.policy != "" {
		p, err := readPolicyFile(flags.policy)
		if err != nil {
			return fail(stderr, err)
		}
		options.Policy = &p
	}
	report, err := firmwaredelta.Compare(ctx, flags.baseline, flags.candidate, options)
	if err != nil {
		return fail(stderr, err)
	}
	var buffer bytes.Buffer
	if flags.format == "json" {
		err = firmwaredelta.WriteJSON(&buffer, report)
	} else {
		err = firmwaredelta.WriteMarkdown(&buffer, report)
	}
	if err != nil {
		return fail(stderr, err)
	}
	if err := ctx.Err(); err != nil {
		return fail(stderr, err)
	}
	if err := write(stdout, buffer.Bytes()); err != nil {
		return fail(stderr, fmt.Errorf("write report: %w", err))
	}
	if report.Counts.Unexpected != 0 {
		return 1
	}
	return 0
}

func parse(args []string) (arguments, error) {
	result := arguments{format: "markdown"}
	if len(args) == 0 || args[0] != "compare" {
		return arguments{}, errors.New("the compare command is required; use --help for usage")
	}
	seen := make(map[string]bool, 4)
	for i := 1; i < len(args); i++ {
		name, value, attached := strings.Cut(args[i], "=")
		var target *string
		switch name {
		case "--baseline":
			target = &result.baseline
		case "--candidate":
			target = &result.candidate
		case "--policy":
			target = &result.policy
		case "--format":
			target = &result.format
		default:
			return arguments{}, fmt.Errorf("unknown argument %q; use --help for usage", name)
		}
		if seen[name] {
			return arguments{}, fmt.Errorf("duplicate flag %s", name)
		}
		seen[name] = true
		if !attached {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "-") {
				return arguments{}, fmt.Errorf("flag %s requires a value (use %s=VALUE for a value starting with '-')", name, name)
			}
			i++
			value = args[i]
		}
		if value == "" {
			return arguments{}, fmt.Errorf("flag %s requires a nonempty value", name)
		}
		*target = value
	}
	if !seen["--baseline"] || !seen["--candidate"] {
		return arguments{}, errors.New("both --baseline and --candidate are required")
	}
	if result.format != "json" && result.format != "markdown" {
		return arguments{}, fmt.Errorf("unsupported format %q; use json or markdown", result.format)
	}
	return result, nil
}

func readPolicyFile(path string) (firmwaredelta.Policy, error) {
	f, err := openPolicy(path)
	if err != nil {
		return firmwaredelta.Policy{}, &firmwaredelta.PolicyError{Op: "open", Err: err}
	}
	before, err := f.Stat()
	if err != nil {
		f.Close()
		return firmwaredelta.Policy{}, &firmwaredelta.PolicyError{Op: "stat", Err: cause(err)}
	}
	p, err := firmwaredelta.ReadPolicy(f)
	after, statErr := f.Stat()
	closeErr := f.Close()
	if err != nil {
		return firmwaredelta.Policy{}, err
	}
	if statErr != nil {
		return firmwaredelta.Policy{}, &firmwaredelta.PolicyError{Op: "stat", Err: cause(statErr)}
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return firmwaredelta.Policy{}, &firmwaredelta.PolicyError{Op: "read", Err: firmwaredelta.ErrInputChanged}
	}
	if closeErr != nil {
		return firmwaredelta.Policy{}, &firmwaredelta.PolicyError{Op: "close", Err: cause(closeErr)}
	}
	return p, nil
}

func cause(err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return pathError.Err
	}
	return err
}

func fail(stderr io.Writer, err error) int {
	_ = write(stderr, []byte(fmt.Sprintf("firmwaredelta: %v\n", err)))
	return 2
}

func write(w io.Writer, data []byte) error {
	if w == nil {
		return errors.New("nil output writer")
	}
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
