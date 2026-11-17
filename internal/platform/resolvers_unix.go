//go:build !windows

package platform

import (
	"errors"
	"io/fs"
	"os"
)

const resolvConfPath = "/etc/resolv.conf"

func systemResolvers() ([]string, error) {
	f, err := os.Open(resolvConfPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return ParseResolvConf(f)
}
