//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// replaceFileAtomically uses same-filesystem rename, then syncs the containing
// directory so the new directory entry survives a crash after SaveConfig has
// reported success.
func replaceFileAtomically(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}

	dir, err := os.Open(filepath.Dir(newPath))
	if err != nil {
		return fmt.Errorf("open containing directory for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()

	// Some Unix filesystems do not implement directory fsync. The rename still
	// has atomic visibility there; do not turn that platform limitation into a
	// permanent inability to save configuration.
	if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
		syncErr = nil
	}
	if syncErr != nil {
		syncErr = fmt.Errorf("sync containing directory: %w", syncErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close containing directory: %w", closeErr)
	}
	return errors.Join(syncErr, closeErr)
}
