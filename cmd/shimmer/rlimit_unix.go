//go:build unix

package main

import "syscall"

// fileLimit reports how many files the process may have open. The Go runtime
// has already raised the soft limit towards the hard limit at startup, as far
// as the system allows. Raising it again here, to a hard limit macOS reports
// as unlimited, succeeded and claimed room for 2^63 files while the kernel
// still stopped at kern.maxfilesperproc, so the pool was never capped there.
func fileLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return min(uint64(lim.Cur), kernelFileLimit()), true
}
