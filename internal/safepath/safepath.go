// Package safepath contains the local-path rules shared by saved command
// output and downloads. Paths accepted here are deliberately portable: a path
// that is safe on Unix must not turn into an absolute, reserved, or otherwise
// special path when the same invocation is run on Windows.
package safepath

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const maxComponentBytes = 120

var windowsVolume = regexp.MustCompile(`^[A-Za-z]:`)

// SanitizeComponent maps untrusted text to one portable filename component.
// A short digest is appended whenever the input changes, avoiding collisions
// such as "a/b" and "a\\b" both becoming the same replacement string.
func SanitizeComponent(value string) string {
	original := value
	value = strings.TrimSpace(value)
	var b strings.Builder
	changed := value != original
	lastUnderscore := false
	for _, r := range value {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
		if allowed && !unicode.IsControl(r) {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		changed = true
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	built := b.String()
	result := strings.TrimRight(built, " .")
	if result != built {
		changed = true
	}
	if result == "" || result == "." || result == ".." || isWindowsReserved(result) {
		result = "item"
		changed = true
	}
	if len(result) > maxComponentBytes {
		result = strings.TrimRight(result[:maxComponentBytes], " .")
		changed = true
	}
	if changed {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(original)))[:10]
		limit := maxComponentBytes - len(digest) - 1
		if len(result) > limit {
			result = strings.TrimRight(result[:limit], " .")
		}
		if result == "" {
			result = "item"
		}
		result += "_" + digest
	}
	return result
}

func isWindowsReserved(component string) bool {
	base := strings.TrimRight(component, " .")
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

// ResolveBelow resolves a portable relative path beneath root. Backslashes are
// treated as separators even on Unix so a path cannot become traversal only
// when moved to Windows.
func ResolveBelow(root, relative string) (string, error) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("resolve output root: %w", err)
	}
	normalized := strings.ReplaceAll(strings.TrimSpace(relative), `\`, "/")
	if normalized == "" {
		return "", errors.New("relative path is empty")
	}
	if strings.ContainsRune(normalized, 0) || strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") || windowsVolume.MatchString(normalized) {
		return "", fmt.Errorf("path %q must be relative", relative)
	}
	parts := strings.Split(normalized, "/")
	cleanParts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("path %q contains traversal", relative)
		}
		if !portableComponent(part) {
			return "", fmt.Errorf("path component %q is not a portable filename", part)
		}
		cleanParts = append(cleanParts, part)
	}
	if len(cleanParts) == 0 {
		return "", errors.New("relative path resolves to the output root")
	}
	target := filepath.Join(append([]string{rootAbs}, cleanParts...)...)
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes output root", relative)
	}
	return target, nil
}

func portableComponent(component string) bool {
	if component == "" || component == "." || component == ".." || isWindowsReserved(component) || strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") {
		return false
	}
	for _, r := range component {
		if unicode.IsControl(r) || strings.ContainsRune(`<>:"|?*`, r) {
			return false
		}
	}
	return true
}

// EnsureDirBelow creates relative beneath root one component at a time and
// refuses to traverse any existing symlink or non-directory component.
func EnsureDirBelow(root, relative string, mode os.FileMode) (string, error) {
	target, err := ResolveBelow(root, relative)
	if err != nil {
		return "", err
	}
	rootAbs, err := ensureRoot(root, mode)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil {
		return "", err
	}
	current := rootAbs
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			if mkdirErr := os.Mkdir(current, mode); mkdirErr != nil {
				return "", mkdirErr
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path component %q is a symlink", current)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("path component %q is not a directory", current)
		}
	}
	return target, nil
}

func ensureRoot(root string, mode os.FileMode) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(abs, mode); err != nil {
			return "", err
		}
		info, err = os.Lstat(abs)
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output root %q is a symlink", abs)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("output root %q is not a directory", abs)
	}
	return abs, nil
}

// AtomicWriteExclusive installs a complete regular file only when the final
// name does not already exist. Linking a same-directory temporary file gives
// atomic no-replace behavior without os.Rename's overwrite semantics.
func AtomicWriteExclusive(root, relative string, data []byte, mode os.FileMode) (retErr error) {
	target, err := ResolveBelow(root, relative)
	if err != nil {
		return err
	}
	rootAbs, err := ensureRoot(root, 0o700)
	if err != nil {
		return err
	}
	parentRel, err := filepath.Rel(rootAbs, filepath.Dir(target))
	if err != nil {
		return err
	}
	if parentRel != "." {
		if _, err := EnsureDirBelow(rootAbs, parentRel, 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %q", target)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".coordinate-output-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); retErr == nil && closeErr != nil {
				retErr = closeErr
			}
		}
		if removeErr := os.Remove(tmpPath); retErr == nil && removeErr != nil && !os.IsNotExist(removeErr) {
			retErr = removeErr
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Link(tmpPath, target); err != nil {
		if _, statErr := os.Lstat(target); statErr == nil {
			return fmt.Errorf("refusing to overwrite existing output %q", target)
		}
		return fmt.Errorf("install output %q: %w", target, err)
	}
	return nil
}
