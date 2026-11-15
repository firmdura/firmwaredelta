// Copyright 2026 FirmwareDelta contributors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/firmwaredelta/internal/model"
)

var fixtureDir string

func TestMain(m *testing.M) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	fixtureDir = filepath.Join(repo, "dist/elf-fixtures")
	cmd := exec.Command("make", "elf-fixtures")
	cmd.Dir = repo
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		_, _ = io.WriteString(os.Stderr, "mandatory original ELF fixture build failed\n")
		os.Exit(2)
	}
	if os.Geteuid() == 0 {
		_, _ = io.WriteString(os.Stderr, "inventory checks require an unprivileged Linux user\n")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func put(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func scanOK(t *testing.T, root string) model.Inventory {
	t.Helper()
	i, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func entries(i model.Inventory) map[string]model.Entry {
	m := make(map[string]model.Entry)
	for _, e := range i.Entries {
		m[e.Path] = e
	}
	return m
}

func TestFilesModesLinksAndRepeatability(t *testing.T) {
	root := t.TempDir()
	secret := []byte("SENTINEL-CONFIG-CONTENTS-MUST-NOT-BE-OUTPUT")
	put(t, filepath.Join(root, "etc/settings"), secret, 0640)
	put(t, filepath.Join(root, "bin/script"), []byte("original synthetic script bytes"), 0751|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
	if err := os.Mkdir(filepath.Join(root, "empty"), 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "etc/settings"), filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "unreadable")
	put(t, outside, []byte("outside-root"), 0000)
	for name, target := range map[string]string{"absolute": outside, "loop": "loop", "dangling": "absent", "etc/link": "../bin/script"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	before := inputState(t, root)
	first, second := scanOK(t, root), scanOK(t, root)
	a, _ := model.CanonicalInventoryJSON(first)
	b, _ := model.CanonicalInventoryJSON(second)
	da, _ := model.InventoryDigest(first)
	db, _ := model.InventoryDigest(second)
	if !bytes.Equal(a, b) || da != db {
		t.Fatal("repeated inventories differ")
	}
	if bytes.Contains(a, secret) || bytes.Contains(a, []byte(root)) {
		t.Fatal("inventory leaked contents or host root")
	}
	if got := inputState(t, root); !reflect.DeepEqual(before, got) {
		t.Fatal("input bytes or modes changed")
	}
	e := entries(first)
	if len(e) != 10 {
		t.Fatalf("want 10 entries including empty directory, got %d: %s", len(e), a)
	}
	if e["etc"].Category != model.CategoryOther || e["etc/settings"].Category != model.CategoryConfig || e["etc/link"].Category != model.CategoryConfig {
		t.Fatal("config precedence is wrong")
	}
	if e["bin/script"].Mode != "7751" || e["bin/script"].Category != model.CategoryExecutable {
		t.Fatalf("special bits lost: %+v", e["bin/script"])
	}
	if e["hardlink"].SHA256 != e["etc/settings"].SHA256 || e["hardlink"].Path == e["etc/settings"].Path {
		t.Fatal("hardlinks not independent evidence")
	}
	for name, want := range map[string]string{"absolute": outside, "loop": "loop", "dangling": "absent"} {
		if e[name].Target == nil || *e[name].Target != want {
			t.Fatalf("literal link target lost: %+v", e[name])
		}
	}
	// Moving identical trees cannot enter the canonical digest.
	other := t.TempDir()
	put(t, filepath.Join(other, "x"), []byte("same"), 0644)
	third := t.TempDir()
	put(t, filepath.Join(third, "x"), []byte("same"), 0644)
	d1, _ := model.InventoryDigest(scanOK(t, other))
	d2, _ := model.InventoryDigest(scanOK(t, third))
	if d1 != d2 {
		t.Fatal("host location affected digest")
	}
}

func inputState(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			value += hex.EncodeToString(h[:])
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += target
		}
		m[rel] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSpecialFilesNeverBlock(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0620); err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "socket"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	i, err := Scan(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	e := entries(i)
	if e["pipe"].Kind != model.KindFIFO || e["socket"].Kind != model.KindSocket {
		t.Fatalf("special metadata missing: %+v", i)
	}
	for _, entry := range i.Entries {
		if entry.Size != nil || entry.SHA256 != "" || entry.ELF != nil || entry.Target != nil {
			t.Fatal("special file has content")
		}
	}
	// Container /dev provides real device nodes without granting mknod or root.
	devices := entries(scanOK(t, "/dev"))
	if devices["null"].Kind != model.KindCharDevice || devices["null"].SHA256 != "" {
		t.Fatal("device metadata was not recorded")
	}
}

func TestLargeFileAndCancellation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "large")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte{0x61, 0x00, 0xff, 0x7e}, 1024)
	h := sha256.New()
	for range 4096 {
		if _, err := f.Write(block); err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(block)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	e := entries(scanOK(t, root))["large"]
	if e.Size == nil || *e.Size != 16*1024*1024 || e.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("streamed bytes were lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Scan(ctx, root)
	var typed *model.ScanError
	if !errors.As(err, &typed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
	// A sparse large regular file keeps the operation busy without large fixture artifacts.
	if err := os.Truncate(file, 1<<30); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err = Scan(ctx, root)
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("scan did not stop promptly: %v", err)
	}
}

func TestArgumentsUnreadabilityAndMalformedEvidence(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	put(t, file, []byte("not an ELF"), 0644)
	link := filepath.Join(t.TempDir(), "rootlink")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", file, link, link + "/", link + "/."} {
		_, err := Scan(context.Background(), path)
		var typed *model.InputError
		if !errors.As(err, &typed) {
			t.Fatalf("root %q: want input error, got %v", path, err)
		}
	}
	for _, path := range []string{filepath.Join(root, "missing"), filepath.Join(root, "missing/child")} {
		_, err := Scan(context.Background(), path)
		var typed *model.ScanError
		if !errors.As(err, &typed) || strings.Contains(err.Error(), root) {
			t.Fatalf("missing root error: %v", err)
		}
	}
	for _, directory := range []bool{false, true} {
		locked := filepath.Join(root, "locked")
		if directory {
			if err := os.Mkdir(locked, 0000); err != nil {
				t.Fatal(err)
			}
		} else {
			put(t, locked, []byte("private"), 0000)
		}
		_, err := Scan(context.Background(), root)
		if err == nil || !errors.Is(err, syscall.EACCES) {
			t.Fatalf("unreadable entry produced success: %v", err)
		}
		if err := os.Chmod(locked, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(locked); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Scan(context.Background(), filepath.Join(fixtureDir, "malformed"))
	if !errors.Is(err, errMalformedELF) {
		t.Fatalf("malformed ELF downgraded: %v", err)
	}
	invalid := filepath.Join(root, string([]byte{0xff}))
	put(t, invalid, nil, 0644)
	if _, err := Scan(context.Background(), root); err == nil {
		t.Fatal("invalid UTF-8 filename accepted")
	}
}

func TestRootSpellingPreservesOSResolution(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	put(t, filepath.Join(base, "candidate/wrong"), nil, 0644)
	put(t, filepath.Join(outside, "candidate/right"), nil, 0644)
	if err := os.Mkdir(filepath.Join(outside, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "subdir"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	// filepath.Join would erase the spelling whose kernel resolution matters.
	got := entries(scanOK(t, base+"/link/../candidate"))
	if _, ok := got["right"]; !ok {
		t.Fatalf("scanned the wrong root: %+v", got)
	}
	if _, ok := got["wrong"]; ok {
		t.Fatal("lexical path cleanup changed the root")
	}
	put(t, filepath.Join(outside, "subdir/child/item"), nil, 0644)
	got = entries(scanOK(t, base+"/link/child"))
	if _, ok := got["item"]; !ok {
		t.Fatal("valid intermediate link root spelling failed")
	}
}

func TestObservedMutationAndDisappearance(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "changing")
	put(t, file, []byte("before"), 0644)
	fd, err := syscall.Open(file, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		t.Fatal(err)
	}
	put(t, file, []byte("after"), 0644)
	_, _, _, err = readRegular(context.Background(), fd, before)
	if !errors.Is(err, model.ErrInputChanged) {
		t.Fatalf("observed mutation accepted: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = readRegular(context.Background(), fd, before)
	if !errors.Is(err, model.ErrInputChanged) {
		t.Fatalf("observed disappearance accepted: %v", err)
	}
	put(t, file, nil, 0644)
	if err := os.Truncate(file, 64<<20); err != nil {
		t.Fatal(err)
	}
	stop, started := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Chmod(file, 0600)
			_ = os.Chmod(file, 0644)
		}
	}()
	<-started
	_, err = Scan(context.Background(), root)
	close(stop)
	wg.Wait()
	if !errors.Is(err, model.ErrInputChanged) {
		t.Fatalf("in-flight mutation accepted: %v", err)
	}
}

func TestEntryAndPathLimits(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		put(t, filepath.Join(root, name), nil, 0644)
	}
	if _, err := scanBounded(context.Background(), root, 3); err != nil {
		t.Fatal("inclusive entry limit failed:", err)
	}
	if _, err := scanBounded(context.Background(), root, 2); !errors.Is(err, model.ErrLimitExceeded) {
		t.Fatalf("entry limit not enforced: %v", err)
	}
	deep := t.TempDir()
	fd, err := syscall.Open(deep, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	name := strings.Repeat("x", 250)
	for range 16 {
		if err := syscall.Mkdirat(fd, name, 0755); err != nil {
			t.Fatal(err)
		}
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = syscall.Close(fd)
		fd = next
	}
	// 16*250 + 15 separators + 1 separator + 80 = 4096 bytes.
	last := strings.Repeat("y", 80)
	if err := syscall.Mkdirat(fd, last, 0755); err != nil {
		t.Fatal(err)
	}
	next, err := syscall.Openat(fd, last, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(fd)
	fd = next
	i := scanOK(t, deep)
	if len(i.Entries) != 17 || len(i.Entries[16].Path) != model.MaxPathBytes {
		t.Fatal("inclusive 4096-byte path rejected")
	}
	if err := syscall.Mkdirat(fd, "x", 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), deep); !errors.Is(err, model.ErrLimitExceeded) {
		t.Fatalf("path byte limit not enforced: %v", err)
	}
}

func TestRealELFFixtures(t *testing.T) {
	base := entries(scanOK(t, filepath.Join(fixtureDir, "baseline")))
	candidate := entries(scanOK(t, filepath.Join(fixtureDir, "candidate")))
	for _, m := range []map[string]model.Entry{base, candidate} {
		program, library := m["usr/bin/maintenance"], m["usr/lib/libmaintenance.so.1"]
		if program.ELF == nil || program.ELF.Class != "64" || program.ELF.Endian != "little" || program.ELF.Machine != 62 || program.Category != model.CategoryExecutable {
			t.Fatalf("program metadata: %+v", program)
		}
		if library.ELF == nil || library.ELF.SONAME != "libmaintenance.so.1" || library.Category != model.CategoryLibrary {
			t.Fatalf("library metadata: %+v", library)
		}
		if !slices.Contains(program.ELF.Needed, "libmaintenance.so.1") || !slices.IsSorted(program.ELF.Needed) {
			t.Fatalf("needed metadata: %+v", program.ELF)
		}
	}
	if slices.Contains(base["usr/bin/maintenance"].ELF.Needed, "libextra.so.1") || !slices.Contains(candidate["usr/bin/maintenance"].ELF.Needed, "libextra.so.1") {
		t.Fatal("real dependency change missing")
	}
	if base["usr/lib/libmaintenance.so.1"].SHA256 == candidate["usr/lib/libmaintenance.so.1"].SHA256 {
		t.Fatal("rebuilt library did not change")
	}
	// ET_EXEC remains executable with all mode execute bits cleared; etc wins.
	root := t.TempDir()
	b, err := os.ReadFile(filepath.Join(fixtureDir, "candidate/usr/bin/maintenance"))
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(root, "program"), b, 0644)
	put(t, filepath.Join(root, "etc/program"), b, 0644)
	got := entries(scanOK(t, root))
	if got["program"].Category != model.CategoryExecutable || got["etc/program"].Category != model.CategoryConfig {
		t.Fatal("ELF/category precedence wrong")
	}
	// Remove section headers. PT_DYNAMIC still contains the same dependencies.
	sectionless := append([]byte{}, b...)
	clear(sectionless[40:48])
	clear(sectionless[58:64])
	metadata, _, err := inspectELF(context.Background(), bytes.NewReader(sectionless), int64(len(sectionless)))
	if err != nil || !reflect.DeepEqual(metadata, candidate["usr/bin/maintenance"].ELF) {
		t.Fatalf("sectionless metadata omitted: %+v, %v", metadata, err)
	}
	// Corrupt a DT_NEEDED string offset; debug/elf.DynString alone silently drops it.
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	corrupt := append([]byte{}, b...)
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			for off := p.Off; off < p.Off+p.Filesz; off += 16 {
				if binary.LittleEndian.Uint64(corrupt[off:]) == uint64(elf.DT_NEEDED) {
					binary.LittleEndian.PutUint64(corrupt[off+8:], ^uint64(0))
					goto corrupted
				}
			}
		}
	}
	t.Fatal("fixture had no dynamic needed entry")
corrupted:
	if _, _, err := inspectELF(context.Background(), bytes.NewReader(corrupt), int64(len(corrupt))); !errors.Is(err, errMalformedELF) {
		t.Fatalf("invalid dependency offset silently lost: %v", err)
	}
}
