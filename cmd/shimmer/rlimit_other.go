//go:build !unix

package main

// fileLimit has no portable answer outside unix, so the pool is left as asked.
func fileLimit() (uint64, bool) { return 0, false }
