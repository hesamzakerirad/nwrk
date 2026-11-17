package fixtures

import (
	"net"
	"sync"
	"testing"
)

// ClosedPort returns a loopback address where nothing listens, so
// connecting to it is refused.
func ClosedPort(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// MuteServer accepts TCP connections and never sends or reads anything, so
// a handshake or request against it waits until its deadline.
func MuteServer(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	return ln.Addr().String()
}

// RawServer accepts connections, writes payload, and closes them. It
// stands in for a server that speaks the wrong protocol.
func RawServer(t testing.TB, payload []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write(payload)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String()
}
