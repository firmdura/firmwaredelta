// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/firmdura/firmwaredelta/internal/model"
)

const (
	oPath             = 0x200000
	atSymlinkNoFollow = 0x100
)

func scan(ctx context.Context, root string) (model.Inventory, error) {
	return scanBounded(ctx, root, model.MaxEntries)
}

func scanBounded(ctx context.Context, root string, maxEntries int) (model.Inventory, error) {
	if ctx == nil || root == "" || strings.ContainsRune(root, 0) {
		return model.Inventory{}, &model.InputError{Op: "root", Err: errors.New("a context and directory root are required")}
	}
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, scanError("cancel", "", err)
	}
	// Remove only terminal slash/dot syntax, so a symlink root cannot acquire
	// directory-following semantics. Do not lexically clean internal '..': its
	// OS meaning depends on preceding symlinks and can identify another root.
	for {
		if len(root) > 1 {
			root = strings.TrimRight(root, "/")
			if root == "" {
				root = "/"
			}
		}
		if !strings.HasSuffix(root, "/.") {
			break
		}
		root = strings.TrimSuffix(root, "/.")
		if root == "" {
			root = "/"
		}
	}
	initial, err := os.Lstat(root)
	if err != nil {
		return model.Inventory{}, scanError("stat root", "", err)
	}
	if !initial.IsDir() || initial.Mode()&os.ModeSymlink != 0 {
		return model.Inventory{}, &model.InputError{Op: "root", Err: errors.New("root must be a directory, not a symlink")}
	}
	fd, err := syscall.Open(root, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return model.Inventory{}, scanError("open root", "", err)
	}
	defer syscall.Close(fd)
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return model.Inventory{}, scanError("stat root", "", err)
	}
	if !sameStat(initial.Sys().(*syscall.Stat_t), &before) || before.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return model.Inventory{}, scanError("root changed", "", model.ErrInputChanged)
	}
	result := model.Inventory{SchemaVersion: model.SchemaVersion, Entries: []model.Entry{}}
	w := walker{ctx: ctx, inventory: &result, maxEntries: maxEntries}
	if err := w.directory(fd, "", before); err != nil {
		return model.Inventory{}, err
	}
	final, err := os.Lstat(root)
	if err != nil || !sameStat(&before, statOf(final)) {
		return model.Inventory{}, scanError("root changed", "", model.ErrInputChanged)
	}
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, scanError("cancel", "", err)
	}
	normal, err := model.NormalizeInventory(result)
	if err != nil {
		return model.Inventory{}, scanError("validate", "", err)
	}
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, scanError("cancel", "", err)
	}
	return normal, nil
}

type walker struct {
	ctx        context.Context
	inventory  *model.Inventory
	maxEntries int
}

func (w *walker) directory(anchor int, path string, before syscall.Stat_t) error {
	if err := w.ctx.Err(); err != nil {
		return scanError("cancel", path, err)
	}
	f, err := reopen(anchor, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return scanError("read directory", path, err)
	}
	defer f.Close()
	// Read bounded batches rather than loading an arbitrarily large directory.
	for {
		if err := w.ctx.Err(); err != nil {
			return scanError("cancel", path, err)
		}
		names, err := f.Readdirnames(128)
		if err != nil && err != io.EOF {
			return scanError("read directory", path, err)
		}
		for _, name := range names {
			child := name
			if path != "" {
				child = path + "/" + name
			}
			if len(w.inventory.Entries) >= w.maxEntries {
				return scanError("entries", child, model.ErrLimitExceeded)
			}
			if len(child) > model.MaxPathBytes {
				return scanError("path", "", model.ErrLimitExceeded)
			}
			if err := model.ValidatePath(child); err != nil {
				return scanError("path", "", err)
			}
			if err := w.entry(anchor, name, child); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(anchor, &after); err != nil {
		return scanError("stat directory", path, err)
	}
	if !sameStat(&before, &after) {
		return scanError("directory changed", path, model.ErrInputChanged)
	}
	return nil
}

func (w *walker) entry(parent int, name, path string) error {
	if err := w.ctx.Err(); err != nil {
		return scanError("cancel", path, err)
	}
	before, err := statAt(parent, name)
	if err != nil {
		return scanError("stat", path, err)
	}
	e := model.Entry{Path: path, Mode: fmt.Sprintf("%04o", before.Mode&07777), Category: model.CategoryOther}
	var elfExec bool
	switch before.Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR:
		// O_PATH obtains only a metadata handle. A racing replacement with a
		// device, FIFO or link is never opened for I/O. Reopening the verified
		// handle via procfs cannot race with replacement of the input pathname.
		fd, err := syscall.Openat(parent, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return scanError("open metadata", path, err)
		}
		defer syscall.Close(fd)
		var opened syscall.Stat_t
		if err := syscall.Fstat(fd, &opened); err != nil {
			return scanError("stat metadata", path, err)
		}
		if !sameStat(&before, &opened) {
			return scanError("entry changed", path, model.ErrInputChanged)
		}
		if before.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			e.Kind = model.KindDirectory
			if strings.HasPrefix(path, "etc/") {
				e.Category = model.CategoryConfig
			}
			w.inventory.Entries = append(w.inventory.Entries, e)
			if err := w.directory(fd, path, opened); err != nil {
				return err
			}
		} else {
			e.Kind = model.KindFile
			content, metadata, executable, err := readRegular(w.ctx, fd, before)
			if err != nil {
				return scanError("read file", path, err)
			}
			e.Size, e.SHA256, e.ELF = &content.Size, content.SHA256, metadata
			elfExec = executable
		}
	case syscall.S_IFLNK:
		e.Kind = model.KindSymlink
		target, err := readlinkAt(parent, name)
		if err != nil {
			return scanError("read symlink", path, err)
		}
		if !utf8.ValidString(target) {
			return scanError("symlink", path, errors.New("target is not valid UTF-8"))
		}
		e.Target = &target
	case syscall.S_IFBLK:
		e.Kind = model.KindBlockDevice
	case syscall.S_IFCHR:
		e.Kind = model.KindCharDevice
	case syscall.S_IFIFO:
		e.Kind = model.KindFIFO
	case syscall.S_IFSOCK:
		e.Kind = model.KindSocket
	default:
		return scanError("kind", path, errors.New("unsupported filesystem entry kind"))
	}
	after, err := statAt(parent, name)
	if err != nil || !sameStat(&before, &after) {
		return scanError("entry changed", path, model.ErrInputChanged)
	}
	if e.Kind == model.KindDirectory {
		return nil
	}
	switch {
	case strings.HasPrefix(path, "etc/"):
		e.Category = model.CategoryConfig
	case e.ELF != nil && e.ELF.SONAME != "":
		e.Category = model.CategoryLibrary
	case e.Kind == model.KindFile && (elfExec || before.Mode&0111 != 0):
		e.Category = model.CategoryExecutable
	}
	if err := e.Validate(); err != nil {
		return scanError("validate", path, err)
	}
	w.inventory.Entries = append(w.inventory.Entries, e)
	return nil
}

func readRegular(ctx context.Context, anchor int, before syscall.Stat_t) (model.Content, *model.ELF, bool, error) {
	f, err := reopen(anchor, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return model.Content{}, nil, false, err
	}
	defer f.Close()
	var opened syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &opened); err != nil {
		return model.Content{}, nil, false, err
	}
	if !sameStat(&before, &opened) || opened.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return model.Content{}, nil, false, model.ErrInputChanged
	}
	h := sha256.New()
	reader := &contextReader{ctx: ctx, r: f}
	n, err := io.CopyBuffer(h, io.LimitReader(reader, before.Size), make([]byte, 128*1024))
	if err != nil {
		return model.Content{}, nil, false, err
	}
	if n != before.Size {
		return model.Content{}, nil, false, model.ErrInputChanged
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 {
		return model.Content{}, nil, false, model.ErrInputChanged
	} else if err != io.EOF {
		if err == nil {
			err = io.ErrNoProgress
		}
		return model.Content{}, nil, false, err
	}
	metadata, executable, err := inspectELF(ctx, f, before.Size)
	if err != nil {
		return model.Content{}, nil, false, err
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &after); err != nil {
		return model.Content{}, nil, false, err
	}
	if !sameStat(&before, &after) {
		return model.Content{}, nil, false, model.ErrInputChanged
	}
	if err := ctx.Err(); err != nil {
		return model.Content{}, nil, false, err
	}
	return model.Content{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, metadata, executable, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func reopen(fd int, flags int) (*os.File, error) {
	n, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", fd), flags|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(n), "inventory handle"), nil
}

func sameStat(a, b *syscall.Stat_t) bool {
	return a != nil && b != nil && a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func statOf(info os.FileInfo) *syscall.Stat_t {
	if info == nil {
		return nil
	}
	st, _ := info.Sys().(*syscall.Stat_t)
	return st
}

func statAt(fd int, name string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return st, err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_NEWFSTATAT, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&st)), atSymlinkNoFollow, 0, 0)
	if errno != 0 {
		return st, errno
	}
	return st, nil
}

func readlinkAt(fd int, name string) (string, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return "", err
	}
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
		if errno != 0 {
			return "", errno
		}
		if n < uintptr(len(buf)) {
			return string(buf[:n]), nil
		}
	}
}

func scanError(op, path string, err error) error {
	// os errors may carry host absolute names. Keep only the underlying cause.
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return &model.ScanError{Op: op, Path: path, Err: err}
}
