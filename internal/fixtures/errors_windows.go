//go:build windows

package fixtures

import "syscall"

// Windows reports socket errors as WSA codes.
var (
	errNoRoute = syscall.Errno(10051) // WSAENETUNREACH
	errRefused = syscall.Errno(10061) // WSAECONNREFUSED
	errReset   = syscall.Errno(10054) // WSAECONNRESET
)
