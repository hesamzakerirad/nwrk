//go:build !windows

package output

import "os"

func enableANSI(*os.File) bool { return true }
