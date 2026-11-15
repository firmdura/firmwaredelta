// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

// Package inventory collects read-only filesystem and static ELF evidence.
// Inputs must remain immutable: change detection is not an atomic snapshot.
package inventory

import (
	"context"

	"github.com/firmdura/firmwaredelta/internal/model"
)

// Scan inventories a Linux amd64 directory without following child symlinks,
// opening special files for I/O, running input programs, or writing inputs.
// The root entry itself is excluded. Any unavailable evidence fails the scan.
func Scan(ctx context.Context, root string) (model.Inventory, error) {
	return scan(ctx, root)
}
