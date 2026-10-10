package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestModelSnapshotOpenRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, []byte("approved bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openStableModelFile(path, before, maxModelFileSize)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("replacement FIFO accepted as model")
		}
	case <-time.After(time.Second):
		// Release a regressed blocking open so the fixture itself cannot hang.
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			syscall.Close(fd)
		}
		t.Fatal("FIFO replacement blocked model open")
	}
}

// Mutate at the first read context check, after descriptor metadata is captured.
// This uses the existing context boundary without adding a production test hook.
type modelMutationContext struct {
	context.Context
	calls  int
	once   sync.Once
	mutate func()
}

func (c *modelMutationContext) Err() error {
	c.calls++
	if c.calls == 2 {
		c.once.Do(c.mutate)
	}
	return c.Context.Err()
}

func TestModelSnapshotRejectsSameSizeWriteWithRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.gguf")
	initial := []byte("approved bytes")
	if err := os.WriteFile(path, initial, 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Unix(1000000000, 0)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var mutationErr error
	ctx := &modelMutationContext{Context: context.Background(), mutate: func() {
		// Ensure separate metadata timestamps on the appliance's Linux filesystem.
		time.Sleep(2 * time.Millisecond)
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			mutationErr = err
			return
		}
		_, mutationErr = f.WriteAt([]byte("modified bytes"), 0)
		closeErr := f.Close()
		if mutationErr == nil {
			mutationErr = closeErr
		}
		if mutationErr == nil {
			mutationErr = os.Chtimes(path, oldTime, oldTime)
		}
	}}
	digest, err := hashFileBoundedContext(ctx, path, maxModelFileSize)
	if mutationErr != nil {
		t.Fatal(mutationErr)
	}
	after, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("fixture did not preserve size and mtime")
	}
	if err == nil || digest != "" {
		t.Fatal("same-size in-place mutation became a verified snapshot")
	}
}
