//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ssh

import "os"

func replaceDownloadedFile(oldPath, newPath string) error {
	if err := os.Link(oldPath, newPath); err != nil {
		return err
	}
	return os.Remove(oldPath)
}
