package main

import (
	"math"
	"syscall"
)

// kernelFileLimit is the cap macOS puts on open files whatever the soft limit
// says. A shell can run "ulimit -n unlimited", and the Go runtime leaves a soft
// limit that is already at the hard limit alone.
func kernelFileLimit() uint64 {
	n, err := syscall.SysctlUint32("kern.maxfilesperproc")
	if err != nil {
		return math.MaxUint64
	}
	return uint64(n)
}
