// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// minimalELF is an original sectionless header; it contains no executable code.
func minimalELF(class byte, order binary.ByteOrder) []byte {
	size := 52
	if class == 2 {
		size = 64
	}
	b := make([]byte, size)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = class, 1, 1
	if order == binary.BigEndian {
		b[5] = 2
	}
	order.PutUint16(b[16:], 2)
	order.PutUint16(b[18:], 243) // unfamiliar-to-host RISC-V is preserved
	order.PutUint32(b[20:], 1)
	if class == 2 {
		order.PutUint16(b[52:], 64)
	} else {
		order.PutUint16(b[40:], 52)
	}
	return b
}

func TestELFHeaderMetadata(t *testing.T) {
	for _, class := range []byte{1, 2} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			b := minimalELF(class, order)
			metadata, executable, err := inspectELF(context.Background(), bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatal(err)
			}
			wantClass, wantEndian := "32", "little"
			if class == 2 {
				wantClass = "64"
			}
			if order == binary.BigEndian {
				wantEndian = "big"
			}
			if metadata == nil || metadata.Class != wantClass || metadata.Endian != wantEndian || metadata.Machine != 243 || metadata.Needed == nil || !executable {
				t.Fatalf("wrong ELF metadata: %+v, executable=%v", metadata, executable)
			}
		}
	}
}

func TestELFMalformedAndNonELF(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("text"), []byte("\x7fEL")} {
		m, _, err := inspectELF(context.Background(), bytes.NewReader(b), int64(len(b)))
		if err != nil || m != nil {
			t.Fatalf("non-ELF: %v, %v", m, err)
		}
	}
	for _, b := range [][]byte{[]byte("\x7fELF"), append([]byte("\x7fELF"), bytes.Repeat([]byte{0xff}, 100)...)} {
		m, _, err := inspectELF(context.Background(), bytes.NewReader(b), int64(len(b)))
		if !errors.Is(err, errMalformedELF) || m != nil {
			t.Fatalf("malformed ELF accepted: %v, %v", m, err)
		}
	}
	wrongHeaderSize := minimalELF(2, binary.LittleEndian)
	clear(wrongHeaderSize[52:54])
	if _, _, err := inspectELF(context.Background(), bytes.NewReader(wrongHeaderSize), int64(len(wrongHeaderSize))); !errors.Is(err, errMalformedELF) {
		t.Fatalf("invalid ELF header size accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := minimalELF(2, binary.LittleEndian)
	_, _, err := inspectELF(ctx, bytes.NewReader(b), int64(len(b)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
