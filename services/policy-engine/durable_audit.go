package main

// Module-local durable evidence stream. JSONL is structured evidence, not an
// authenticated chain or an external rollback anchor. Keep the two service copies aligned.
import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const maxAuditBytes int64 = 64 << 20
const maxAuditRecord = 8192

var errAuditUnavailable = errors.New("durable audit evidence unavailable")

type auditRecord struct {
	Version   int             `json:"version"`
	Sequence  uint64          `json:"sequence"`
	Timestamp string          `json:"timestamp"`
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data"`
}
type durableAudit struct {
	mu                sync.Mutex
	file, directory   *os.File
	path              string
	info, dirInfo     os.FileInfo
	sequence          uint64
	failed            bool
	write             func([]byte) (int, error)
	syncFile, syncDir func() error
}

func auditHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func privateAuditFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1 && st.Uid == uint32(os.Geteuid())
}
func safeAuditDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && (info.Mode().Perm()&0022 == 0 || info.Mode()&os.ModeSticky != 0)
}
func sameAuditFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	sa, oka := a.Sys().(*syscall.Stat_t)
	sb, okb := b.Sys().(*syscall.Stat_t)
	return oka && okb && sa.Ctim == sb.Ctim
}
func openDurableAudit(path string, configure ...func(*durableAudit)) (_ *durableAudit, result error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errAuditUnavailable
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, errAuditUnavailable
	}
	dir, err := os.Open(parent)
	if err != nil {
		return nil, errAuditUnavailable
	}
	a := &durableAudit{directory: dir, path: path}
	defer func() {
		if result != nil {
			if a.file != nil {
				a.file.Close()
			}
			dir.Close()
		}
	}()
	a.dirInfo, err = dir.Stat()
	if err != nil || !safeAuditDirectory(a.dirInfo) {
		return nil, errAuditUnavailable
	}
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_CREAT|syscall.O_APPEND|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errAuditUnavailable
	}
	a.file = os.NewFile(uintptr(fd), path)
	a.info, err = a.file.Stat()
	if err != nil || !privateAuditFile(a.info) || a.info.Size() > maxAuditBytes {
		return nil, errAuditUnavailable
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errAuditUnavailable
	}
	a.write = a.file.Write
	a.syncFile = a.file.Sync
	a.syncDir = dir.Sync
	for _, hook := range configure {
		hook(a)
	}
	if a.info.Size() > 0 {
		var last [1]byte
		if _, err = a.file.ReadAt(last[:], a.info.Size()-1); err != nil || last[0] != '\n' {
			return nil, errAuditUnavailable
		}
	}
	scanner := bufio.NewScanner(io.NewSectionReader(a.file, 0, a.info.Size()))
	scanner.Buffer(make([]byte, 1024), maxAuditRecord)
	for scanner.Scan() {
		var record auditRecord
		dec := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		dec.DisallowUnknownFields()
		if dec.Decode(&record) != nil {
			return nil, errAuditUnavailable
		}
		var trailing any
		if dec.Decode(&trailing) != io.EOF || record.Version != 1 || record.Sequence != a.sequence+1 || len(record.Event) == 0 || len(record.Event) > 48 || len(record.Data) == 0 || record.Data[0] != '{' {
			return nil, errAuditUnavailable
		}
		if _, err = time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
			return nil, errAuditUnavailable
		}
		a.sequence = record.Sequence
	}
	if scanner.Err() != nil || a.checkLocked(0) != nil || a.syncFile() != nil || a.syncDir() != nil {
		return nil, errAuditUnavailable
	}
	return a, nil
}
func (a *durableAudit) checkLocked(pending int64) error {
	if a == nil || a.failed || a.file == nil {
		return errAuditUnavailable
	}
	fail := func() error { a.failed = true; return errAuditUnavailable }
	info, err := a.file.Stat()
	if err != nil || !privateAuditFile(info) || !sameAuditFile(a.info, info) || pending < 0 || info.Size() >= maxAuditBytes || info.Size() > maxAuditBytes-pending {
		return fail()
	}
	current, err := os.Lstat(a.path)
	if err != nil || !privateAuditFile(current) || !sameAuditFile(info, current) {
		return fail()
	}
	dir, err := os.Lstat(filepath.Dir(a.path))
	if err != nil || !safeAuditDirectory(dir) || !os.SameFile(a.dirInfo, dir) || a.dirInfo.Mode() != dir.Mode() {
		return fail()
	}
	return nil
}
func (a *durableAudit) Ready() error {
	if a == nil {
		return errAuditUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkLocked(0)
}
func (a *durableAudit) Append(event string, value any) error {
	if a == nil {
		return errAuditUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := func() error { a.failed = true; return errAuditUnavailable }
	data, err := json.Marshal(value)
	if err != nil {
		return fail()
	}
	record := auditRecord{Version: 1, Sequence: a.sequence + 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Event: event, Data: data}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded)+1 >= maxAuditRecord || len(event) == 0 || len(event) > 48 {
		return fail()
	}
	encoded = append(encoded, '\n')
	if a.checkLocked(int64(len(encoded))) != nil {
		return fail()
	}
	n, err := a.write(encoded)
	if err != nil || n != len(encoded) {
		return fail()
	}
	if a.syncFile() != nil || a.syncDir() != nil {
		return fail()
	}
	updated, err := a.file.Stat()
	if err != nil || updated.Size() != a.info.Size()+int64(n) {
		return fail()
	}
	a.info = updated
	if a.checkLocked(0) != nil {
		return fail()
	}
	a.sequence++
	return nil
}
func (a *durableAudit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.checkLocked(0)
	err = errors.Join(err, a.syncFile(), a.syncDir(), a.file.Close(), a.directory.Close())
	a.file = nil
	a.failed = true
	if err != nil {
		return fmt.Errorf("close audit: %w", errAuditUnavailable)
	}
	return nil
}
