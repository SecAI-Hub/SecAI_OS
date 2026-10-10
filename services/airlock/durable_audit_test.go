package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func setupAudit(t *testing.T) {
	t.Helper()
	previous := auditLog
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	current := auditLog
	t.Cleanup(func() { _ = current.Close(); auditLog = previous })
}
func newTestAudit(t *testing.T) *durableAudit {
	t.Helper()
	a, err := openDurableAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func TestAuditSerializedDurableRecords(t *testing.T) {
	a := newTestAudit(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Append("test", map[string]string{"state": "accepted"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var sequence uint64
	for scanner.Scan() {
		var rec auditRecord
		if json.Unmarshal(scanner.Bytes(), &rec) != nil {
			t.Fatal("invalid record")
		}
		sequence++
		if rec.Sequence != sequence {
			t.Fatal("sequence")
		}
	}
	if sequence != 32 {
		t.Fatal(sequence)
	}
	reopened, err := openDurableAudit(a.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.sequence != 32 {
		t.Fatal(reopened.sequence)
	}
}
func TestAuditRejectsOtherWriter(t *testing.T) {
	a := newTestAudit(t)
	if second, err := openDurableAudit(a.path); err == nil {
		second.Close()
		t.Fatal("second writer accepted")
	}
}
func TestAuditStorageFailureLatches(t *testing.T) {
	for _, kind := range []string{"enospc", "short-write", "file-sync", "directory-sync", "record-bound"} {
		t.Run(kind, func(t *testing.T) {
			a := newTestAudit(t)
			original := a.write
			fs, ds := a.syncFile, a.syncDir
			value := map[string]string{"state": "accepted"}
			switch kind {
			case "enospc":
				a.write = func([]byte) (int, error) { return 0, syscall.ENOSPC }
			case "short-write":
				a.write = func(p []byte) (int, error) { return original(p[:len(p)/2]) }
			case "file-sync":
				a.syncFile = func() error { return syscall.EIO }
			case "directory-sync":
				a.syncDir = func() error { return syscall.EIO }
			case "record-bound":
				value["state"] = strings.Repeat("x", maxAuditRecord)
			}
			if a.Append("test", value) == nil {
				t.Fatal("failure ignored")
			}
			a.write = original
			a.syncFile = fs
			a.syncDir = ds
			if a.Ready() == nil || a.Append("test", map[string]string{}) == nil {
				t.Fatal("failure latch cleared")
			}
			if kind == "short-write" {
				_ = a.Close()
				if b, err := openDurableAudit(a.path); err == nil {
					b.Close()
					t.Fatal("partial tail accepted on restart")
				}
			}
		})
	}
}
func TestAuditRejectsMalformedExistingStorage(t *testing.T) {
	for _, data := range []string{"{}", "{}\n", "null\n", "\n", "{\"version\":1}\n", strings.Repeat("x", maxAuditRecord) + "\n"} {
		t.Run("tail", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if os.WriteFile(path, []byte(data), 0600) != nil {
				t.Fatal("fixture")
			}
			if a, err := openDurableAudit(path); err == nil {
				a.Close()
				t.Fatal("invalid existing evidence accepted")
			}
		})
	}
}
func TestAuditRejectsUnsafeStorage(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "fifo", "missing-parent", "unsafe-parent", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "hardlink":
				os.Link(path, path+".link")
			case "mode":
				os.Chmod(path, 0640)
			case "fifo":
				os.Remove(path)
				syscall.Mkfifo(path, 0600)
			case "missing-parent":
				path = filepath.Join(dir, "missing", "audit")
			case "unsafe-parent":
				os.Chmod(dir, 0777)
			case "oversize":
				os.Truncate(path, maxAuditBytes+1)
			}
			if a, err := openDurableAudit(path); err == nil {
				a.Close()
				t.Fatal("unsafe storage accepted")
			}
		})
	}
}
func TestAuditLivePathDriftLatches(t *testing.T) {
	for _, kind := range []string{"replacement", "truncate", "same-size-write", "parent-replacement", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			a := newTestAudit(t)
			if err := a.Append("test", map[string]string{}); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "replacement":
				os.Rename(a.path, a.path+".old")
				os.WriteFile(a.path, nil, 0600)
			case "truncate":
				os.Truncate(a.path, 0)
			case "same-size-write":
				f, _ := os.OpenFile(a.path, os.O_WRONLY, 0)
				f.WriteAt([]byte("X"), 0)
				f.Close()
			case "parent-replacement":
				dir := filepath.Dir(a.path)
				os.Rename(dir, dir+".old")
				defer os.RemoveAll(dir + ".old")
				os.Mkdir(dir, 0700)
			case "mode":
				os.Chmod(a.path, 0640)
			case "hardlink":
				os.Link(a.path, a.path+".link")
			}
			if a.Ready() == nil || a.Append("test", map[string]string{}) == nil {
				t.Fatal("path drift accepted")
			}
		})
	}
}
func TestAuditStartupRequiresStorage(t *testing.T) {
	previous := auditLog
	defer func() { auditLog = previous }()
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "absent", "audit"))
	if initAuditLog() == nil {
		t.Fatal("startup accepted missing storage")
	}
}
func TestAuditCloseReportsFailure(t *testing.T) {
	a := newTestAudit(t)
	a.syncFile = func() error { return io.ErrClosedPipe }
	if err := a.Close(); !errors.Is(err, errAuditUnavailable) {
		t.Fatal(err)
	}
}

func TestAuditStartupPropagatesSyncErrors(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run("sync", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			a, err := openDurableAudit(path, func(a *durableAudit) {
				if directory {
					a.syncDir = func() error { return syscall.EIO }
				} else {
					a.syncFile = func() error { return syscall.EIO }
				}
			})
			if err == nil {
				a.Close()
				t.Fatal("startup ignored sync failure")
			}
			reopened, err := openDurableAudit(path)
			if err != nil {
				t.Fatal("failed startup retained lock", err)
			}
			reopened.Close()
		})
	}
}
func TestAuditAppendCapFailsClosed(t *testing.T) {
	a := newTestAudit(t)
	if err := a.file.Truncate(maxAuditBytes - 1); err != nil {
		t.Fatal(err)
	}
	var err error
	a.info, err = a.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if a.Append("test", map[string]string{}) == nil || a.Ready() == nil {
		t.Fatal("audit size ceiling bypassed")
	}
}
