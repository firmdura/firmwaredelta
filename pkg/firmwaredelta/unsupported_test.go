// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package firmwaredelta_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	f "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func TestUnsupportedCompareHost(t *testing.T) {
	r, err := f.Compare(context.Background(), ".", ".", f.Options{})
	var typed *f.InputError
	if !errors.Is(err, f.ErrUnsupportedHost) || !errors.As(err, &typed) || !reflect.DeepEqual(r, f.Report{}) {
		t.Fatalf("unsupported host lost typed failure: %+v %v", r, err)
	}
}
