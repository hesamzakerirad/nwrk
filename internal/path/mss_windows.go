//go:build windows

package path

import "net"

// Windows does not report the segment size of a connection this way.
func segmentSize(net.Conn) (int, bool) { return 0, false }
