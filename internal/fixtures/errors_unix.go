//go:build !windows

package fixtures

import "syscall"

// Platform socket errors, as the operating system reports them.
var (
	errNoRoute = syscall.ENETUNREACH
	errRefused = syscall.ECONNREFUSED
	errReset   = syscall.ECONNRESET
)
