package main

import (
	"syscall"
	"testing"
)

// macOS stops every process at kern.maxfilesperproc open files, whatever its
// rlimit says. fileLimit used to raise the soft limit to a hard limit reported
// as unlimited, which succeeded, and then claimed room for 2^63 files: the
// pool was never capped, and workers past the real limit failed every dial
// with "too many open files", recorded as dead proxies.
func TestFileLimitWithinKernelCap(t *testing.T) {
	kernel, err := syscall.SysctlUint32("kern.maxfilesperproc")
	if err != nil {
		t.Skipf("kern.maxfilesperproc: %v", err)
	}
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
			t.Errorf("restore the open-file limit: %v", err)
		}
	})

	check := func(t *testing.T) {
		t.Helper()
		limit, ok := fileLimit()
		if !ok {
			t.Fatal("no open-file limit read")
		}
		if limit > uint64(kernel) {
			t.Errorf("fileLimit %d, past kern.maxfilesperproc %d", limit, kernel)
		}
		if n := capWorkers(1<<30, true); n > int(kernel)-32 {
			t.Errorf("capWorkers kept %d workers, past kern.maxfilesperproc %d less headroom", n, kernel)
		}
	}

	t.Run("as started", check)

	// As started from a shell that ran "ulimit -n unlimited": the soft limit
	// is already the hard one, so the Go runtime leaves it alone.
	t.Run("soft limit at the hard limit", func(t *testing.T) {
		raised := syscall.Rlimit{Cur: orig.Max, Max: orig.Max}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &raised); err != nil {
			t.Skipf("raise the soft limit to %d: %v", orig.Max, err)
		}
		check(t)
	})
}
