//go:build windows

package platform

import "fmt"

// The routing table is not read on Windows: doing it natively means calling
// the IP Helper API directly, which is not yet implemented. Whether a
// default route exists is still detected by nw doctor.
func routes() ([]Route, error) {
	return nil, fmt.Errorf("reading the routing table on Windows: %w", ErrUnsupported)
}
