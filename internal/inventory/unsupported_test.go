// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/firmdura/firmwaredelta/internal/model"
)

func TestUnsupportedHost(t *testing.T) {
	_, err := Scan(context.Background(), ".")
	var typed *model.InputError
	if !errors.As(err, &typed) || !errors.Is(err, model.ErrUnsupportedHost) {
		t.Fatalf("want typed unsupported-host error, got %v", err)
	}
}
