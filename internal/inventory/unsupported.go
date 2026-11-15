// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package inventory

import (
	"context"

	"github.com/firmdura/firmwaredelta/internal/model"
)

func scan(context.Context, string) (model.Inventory, error) {
	return model.Inventory{}, &model.InputError{Op: "host", Err: model.ErrUnsupportedHost}
}
