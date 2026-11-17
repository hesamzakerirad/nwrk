//go:build !windows

package errclass

import (
	"errors"
	"syscall"
)

var (
	refusedErrnos     = []error{syscall.ECONNREFUSED}
	resetErrnos       = []error{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE}
	unreachableErrnos = []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN}
)

func isErrno(err error, set []error) bool {
	for _, e := range set {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
