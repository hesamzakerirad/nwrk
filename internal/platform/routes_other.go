//go:build !linux && !darwin && !windows

package platform

import "fmt"

func routes() ([]Route, error) {
	return nil, fmt.Errorf("reading the routing table on this system: %w", ErrUnsupported)
}
