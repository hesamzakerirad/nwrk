package fixtures

import (
	"net"
	"os"
)

func dialError(errno error) error {
	return &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", errno)}
}

// NoRouteError is the error a dial returns when the system has no route,
// in the form the running operating system produces it.
func NoRouteError() error { return dialError(errNoRoute) }

// RefusedError is the error of a refused connection.
func RefusedError() error { return dialError(errRefused) }

// ResetError is the error of a connection reset by the peer.
func ResetError() error { return dialError(errReset) }
