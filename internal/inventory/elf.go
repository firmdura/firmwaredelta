// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/firmdura/firmwaredelta/internal/model"
)

var errMalformedELF = errors.New("malformed ELF metadata")

type contextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(p, off)
}

func inspectELF(ctx context.Context, source io.ReaderAt, size int64) (*model.ELF, bool, error) {
	r := contextReaderAt{ctx: ctx, r: source}
	var magic [4]byte
	n, err := r.ReadAt(magic[:], 0)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if n < 4 || !bytes.Equal(magic[:], []byte(elf.ELFMAG)) {
		return nil, false, nil
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, false, elfError(ctx)
	}
	defer f.Close()
	headerSize, headerSizeOffset := uint16(52), int64(40)
	if f.Class == elf.ELFCLASS64 {
		headerSize, headerSizeOffset = 64, 52
	}
	var encodedSize [2]byte
	if _, err := r.ReadAt(encodedSize[:], headerSizeOffset); err != nil {
		return nil, false, elfError(ctx)
	}
	if f.ByteOrder.Uint16(encodedSize[:]) != headerSize {
		return nil, false, errMalformedELF
	}
	for _, p := range f.Progs {
		if !fileRange(p.Off, p.Filesz, size) {
			return nil, false, errMalformedELF
		}
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOBITS && !fileRange(s.Offset, s.FileSize, size) {
			return nil, false, errMalformedELF
		}
	}
	soname, needed, err := dynamicStrings(ctx, r, f, size)
	if err != nil {
		return nil, false, err
	}
	metadata := &model.ELF{Class: "32", Endian: "little", Machine: uint16(f.Machine), SONAME: soname, Needed: needed}
	if f.Class == elf.ELFCLASS64 {
		metadata.Class = "64"
	}
	if f.Data == elf.ELFDATA2MSB {
		metadata.Endian = "big"
	}
	if err := metadata.Validate(); err != nil {
		return nil, false, errMalformedELF
	}
	return metadata, f.Type == elf.ET_EXEC, nil
}

func fileRange(off, length uint64, size int64) bool {
	return size >= 0 && off <= uint64(size) && length <= uint64(size)-off
}

// debug/elf supplies validated headers, but DynString silently ignores invalid
// string offsets and uses only section headers. Parse bounded dynamic entries
// strictly, including PT_DYNAMIC on sectionless executable/shared objects.
func dynamicStrings(ctx context.Context, r io.ReaderAt, f *elf.File, size int64) (string, []string, error) {
	var off, length uint64
	var section *elf.Section
	var program *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			if program != nil {
				return "", nil, errMalformedELF
			}
			program, off, length = p, p.Off, p.Filesz
		}
	}
	for _, s := range f.Sections {
		if s.Type == elf.SHT_DYNAMIC {
			if section != nil {
				return "", nil, errMalformedELF
			}
			section = s
		}
	}
	if program == nil && section == nil {
		return "", []string{}, nil
	}
	if program == nil {
		off, length = section.Offset, section.FileSize
	}
	if section != nil && program != nil && (section.Offset != off || section.FileSize != length) {
		return "", nil, errMalformedELF
	}
	stride := uint64(8)
	if f.Class == elf.ELFCLASS64 {
		stride = 16
	}
	if length == 0 || length%stride != 0 || !fileRange(off, length, size) {
		return "", nil, errMalformedELF
	}
	var stringAddress, stringSize uint64
	var hasAddress, hasSize, terminated bool
	var neededOffsets, sonameOffsets []uint64
	var entry [16]byte
	for pos := uint64(0); pos < length; pos += stride {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if _, err := r.ReadAt(entry[:stride], int64(off+pos)); err != nil {
			return "", nil, elfError(ctx)
		}
		var tag, value uint64
		if stride == 16 {
			tag, value = f.ByteOrder.Uint64(entry[:8]), f.ByteOrder.Uint64(entry[8:])
		} else {
			tag, value = uint64(f.ByteOrder.Uint32(entry[:4])), uint64(f.ByteOrder.Uint32(entry[4:8]))
		}
		if elf.DynTag(tag) == elf.DT_NULL {
			terminated = true
			break
		}
		switch elf.DynTag(tag) {
		case elf.DT_STRTAB:
			if hasAddress {
				return "", nil, errMalformedELF
			}
			stringAddress, hasAddress = value, true
		case elf.DT_STRSZ:
			if hasSize {
				return "", nil, errMalformedELF
			}
			stringSize, hasSize = value, true
		case elf.DT_NEEDED:
			neededOffsets = append(neededOffsets, value)
		case elf.DT_SONAME:
			sonameOffsets = append(sonameOffsets, value)
		}
	}
	if !terminated || len(sonameOffsets) > 1 {
		return "", nil, errMalformedELF
	}
	var stringOffset uint64
	if program != nil {
		if hasAddress != hasSize {
			return "", nil, errMalformedELF
		}
		if hasAddress {
			mapped := false
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && stringAddress >= p.Vaddr && stringAddress-p.Vaddr <= p.Filesz && stringSize <= p.Filesz-(stringAddress-p.Vaddr) {
					candidate := p.Off + (stringAddress - p.Vaddr)
					if mapped && candidate != stringOffset {
						return "", nil, errMalformedELF
					}
					stringOffset, mapped = candidate, true
				}
			}
			if !mapped {
				return "", nil, errMalformedELF
			}
		}
	} else {
		if uint64(section.Link) >= uint64(len(f.Sections)) {
			return "", nil, errMalformedELF
		}
		str := f.Sections[section.Link]
		if str.Type != elf.SHT_STRTAB || str.Flags&elf.SHF_COMPRESSED != 0 {
			return "", nil, errMalformedELF
		}
		stringOffset, stringSize = str.Offset, str.FileSize
		hasAddress = true
	}
	if !fileRange(stringOffset, stringSize, size) || ((len(neededOffsets) > 0 || len(sonameOffsets) > 0) && !hasAddress) {
		return "", nil, errMalformedELF
	}
	readString := func(index uint64) (string, error) {
		if index >= stringSize {
			return "", errMalformedELF
		}
		var text []byte
		var buf [1024]byte
		for pos := index; pos < stringSize; {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			n := min(uint64(len(buf)), stringSize-pos)
			if _, err := r.ReadAt(buf[:n], int64(stringOffset+pos)); err != nil {
				return "", elfError(ctx)
			}
			if end := bytes.IndexByte(buf[:n], 0); end >= 0 {
				text = append(text, buf[:end]...)
				if !utf8.Valid(text) {
					return "", errMalformedELF
				}
				return string(text), nil
			}
			text = append(text, buf[:n]...)
			pos += n
		}
		return "", errMalformedELF
	}
	soname := ""
	if len(sonameOffsets) == 1 {
		var err error
		soname, err = readString(sonameOffsets[0])
		if err != nil {
			return "", nil, err
		}
	}
	needed := make([]string, 0, len(neededOffsets))
	for _, index := range neededOffsets {
		s, err := readString(index)
		if err != nil {
			return "", nil, err
		}
		needed = append(needed, s)
	}
	slices.Sort(needed)
	return soname, slices.Compact(needed), nil
}

func elfError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Parser errors can contain untrusted bytes; diagnostics expose no contents.
	return errMalformedELF
}
