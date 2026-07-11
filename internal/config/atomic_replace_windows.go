//go:build windows

package config

import "golang.org/x/sys/windows"

// replaceFileAtomically replaces an existing destination on Windows. os.Rename
// does not provide replace-existing semantics there, so use MoveFileEx with
// both replacement and write-through flags.
func replaceFileAtomically(oldPath, newPath string) error {
	oldPathUTF16, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPathUTF16, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(
		oldPathUTF16,
		newPathUTF16,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
