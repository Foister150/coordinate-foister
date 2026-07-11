//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package config

import "os"

// Non-Unix platforms without a stronger replacement primitive retain the
// platform's native rename behavior. Supported release platforms use one of
// the durability-aware implementations in the other files.
func replaceFileAtomically(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
