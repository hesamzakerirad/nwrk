//go:build windows

package errclass

import (
	"errors"
	"syscall"
)

// Windows reports socket errors as WSA codes, which the syscall package does
// not map onto its portable constants.
var (
	refusedErrnos     = []error{syscall.Errno(10061)}                                             // WSAECONNREFUSED
	resetErrnos       = []error{syscall.Errno(10054), syscall.Errno(10053)}                       // WSAECONNRESET, WSAECONNABORTED
	unreachableErrnos = []error{syscall.Errno(10051), syscall.Errno(10065), syscall.Errno(10050)} // WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN
)

func isErrno(err error, set []error) bool {
	for _, e := range set {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
