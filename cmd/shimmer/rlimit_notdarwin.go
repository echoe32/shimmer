//go:build unix && !darwin

package main

import "math"

// kernelFileLimit adds no cap of its own outside macOS: the soft limit is it.
func kernelFileLimit() uint64 { return math.MaxUint64 }
