package utils

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"inet.af/netaddr"

	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/safepath"
)

const DefaultMaxTargets int64 = 65_536

func ParseIPs(targets string) ([]netaddr.IP, []string, error) {
	return ParseIPsWithLimit(targets, DefaultMaxTargets)
}

// ParseIPsWithLimit parses, deduplicates, and sorts targets while refusing to
// materialize more than maxTargets addresses. The limit is checked against the
// compact IP set before its ranges are enumerated.
func ParseIPsWithLimit(targets string, maxTargets int64) ([]netaddr.IP, []string, error) {
	logger.Debug("Starting ParseIPs with targets:", targets)
	if maxTargets <= 0 {
		return nil, nil, fmt.Errorf("maximum target count must be greater than zero (got %d)", maxTargets)
	}

	targetTokens := strings.Split(targets, ",")
	logger.Debug("Split targets into tokens:", targetTokens)

	ipSetBuilder := netaddr.IPSetBuilder{}

	for _, token := range targetTokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		logger.Debug("Processing token:", token)
		if err := addTargetToSet(token, &ipSetBuilder, maxTargets); err != nil {
			logger.Err("Error adding target to IP set:", err)
			return nil, nil, err
		}
	}

	ipSet, err := ipSetBuilder.IPSet()
	if err != nil {
		logger.Err("Error building IP set:", err)
		return nil, nil, fmt.Errorf("error building IP set: %w", err)
	}

	logger.Debug("Built IP set:", ipSet)

	targetCount := ipSetCardinality(ipSet)
	limit := new(big.Int).SetInt64(maxTargets)
	if targetCount.Cmp(limit) > 0 {
		return nil, nil, fmt.Errorf("target set expands to %s addresses, exceeding --max-targets=%d", targetCount.String(), maxTargets)
	}

	maxInt := int64(^uint(0) >> 1)
	if !targetCount.IsInt64() || targetCount.Int64() > maxInt {
		return nil, nil, fmt.Errorf("target set contains %s addresses, too many to materialize on this platform", targetCount.String())
	}

	individualIPs, stringAddresses := extractIPsAndRanges(ipSet, int(targetCount.Int64()))

	logger.Debug("Extracted individual IPs:", individualIPs)
	logger.Debug("Extracted string addresses:", stringAddresses)

	return individualIPs, stringAddresses, nil
}

func GenerateRandomFileName(length int) string {
	logger.Debug("Starting GenerateRandomFileName with length:", length)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		logger.Err("Error generating random bytes:", err)
		panic(err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	filename := string(b)
	logger.Debug("Generated random file name:", filename)
	return filename
}

func Dos2unix(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var buffer bytes.Buffer

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %v", err)
		}

		line = bytes.Replace(line, []byte("\r"), []byte(""), -1)
		buffer.Write(line)

		if err == io.EOF {
			break
		}
	}

	file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %v", err)
	}
	defer file.Close()

	_, err = file.Write(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

func extractTarReader(tarReader *tar.Reader, destDir string, portableNames bool) error {
	root, err := prepareExtractionRoot(destDir)
	if err != nil {
		return err
	}

	portableTargets := make(map[string]string)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		entryName := header.Name
		if portableNames {
			entryName = portableTarEntryName(entryName)
		}
		target, err := extractionTarget(root, entryName)
		if err != nil {
			return fmt.Errorf("unsafe tar entry %q: %w", header.Name, err)
		}
		if portableNames && target != root {
			rel, relErr := filepath.Rel(root, target)
			if relErr != nil {
				return relErr
			}
			key := strings.ToLower(filepath.ToSlash(rel))
			if previous, exists := portableTargets[key]; exists {
				return fmt.Errorf("portable archive name collision between %q and %q", previous, header.Name)
			}
			portableTargets[key] = header.Name
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := ensureExtractionDirs(root, target); err != nil {
				return fmt.Errorf("failed to create dir '%s': %w", target, err)
			}
		case tar.TypeReg, byte(0): // byte(0) is the legacy tar regular-file marker.
			if target == root {
				return fmt.Errorf("invalid regular-file path %q", header.Name)
			}
			if err := ensureExtractionDirs(root, filepath.Dir(target)); err != nil {
				return fmt.Errorf("failed to create parent dir for '%s': %w", target, err)
			}
			if err := removeExtractionTarget(target); err != nil {
				return fmt.Errorf("failed to prepare file '%s': %w", target, err)
			}
			outFile, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return fmt.Errorf("failed to create file '%s': %w", target, err)
			}
			bufferedFile := bufio.NewWriterSize(outFile, 64*1024)
			_, copyErr := io.Copy(bufferedFile, tarReader)
			flushErr := bufferedFile.Flush()
			closeErr := outFile.Close()
			if copyErr != nil || flushErr != nil || closeErr != nil {
				removeErr := os.Remove(target)
				if copyErr != nil {
					return fmt.Errorf("failed to write file '%s': %w", target, errors.Join(copyErr, flushErr, closeErr, removeErr))
				}
				if flushErr != nil {
					return fmt.Errorf("failed to flush file '%s': %w", target, errors.Join(flushErr, closeErr, removeErr))
				}
				return fmt.Errorf("failed to close file '%s': %w", target, errors.Join(closeErr, removeErr))
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported link entry %q", header.Name)
		default:
			return fmt.Errorf("unsupported tar entry type %d for %q", header.Typeflag, header.Name)
		}
	}
	return nil
}

// portableTarEntryName maps every remote-derived path component to the same
// portable alphabet used for host/output labels. Dot traversal is deliberately
// left intact so extractionTarget rejects it rather than disguising it.
func portableTarEntryName(name string) string {
	normalized := strings.ReplaceAll(name, `\`, "/")
	parts := strings.Split(normalized, "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		parts[index] = safepath.SanitizeComponent(part)
	}
	return pathpkg.Clean(strings.Join(parts, "/"))
}

func prepareExtractionRoot(destDir string) (string, error) {
	if strings.TrimSpace(destDir) == "" {
		return "", fmt.Errorf("destination directory is empty")
	}

	root, err := filepath.Abs(filepath.Clean(destDir))
	if err != nil {
		return "", fmt.Errorf("failed to resolve destination directory: %w", err)
	}
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("destination directory is a symlink")
		}
		if !info.IsDir() {
			return "", fmt.Errorf("destination path is not a directory")
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to inspect destination directory: %w", err)
	} else if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Resolve symlinks in trusted parent components (for example, /tmp on some
	// platforms) so all subsequent containment checks use one canonical root.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("failed to resolve destination directory: %w", err)
	}
	return filepath.Clean(root), nil
}

func extractionTarget(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("entry name is empty")
	}

	// Treat backslashes as archive separators on every OS. Otherwise an archive
	// can be safe on Unix but become absolute/traversing when extracted on Windows.
	name = filepath.FromSlash(strings.ReplaceAll(name, `\`, "/"))
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("entry name is absolute")
	}

	target := filepath.Join(root, filepath.Clean(name))
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve entry path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("entry escapes destination")
	}
	return target, nil
}

// ensureExtractionDirs creates one directory component at a time and refuses
// to traverse symlinks. This prevents an earlier archive entry (or an existing
// path in the destination) from redirecting a later file write outside root.
func ensureExtractionDirs(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("directory escapes destination")
	}
	if rel == "." {
		return nil
	}

	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("path component %q is not a directory", current)
		}
	}
	return nil
}

func removeExtractionTarget(target string) error {
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("target already exists (%s); refusing to overwrite", info.Mode())
}

func ExtractTarGz(archivePath string, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open tar.gz: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return extractTarReader(tar.NewReader(gzReader), destDir, false)
}

func ExtractTar(archivePath string, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open tar: %w", err)
	}
	defer f.Close()

	return extractTarReader(tar.NewReader(f), destDir, false)
}

// ExtractTarGzFromReader extracts a gzipped tar stream directly from a reader (e.g. SSH stdout pipe)
func ExtractTarGzFromReader(r io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return extractTarReader(tar.NewReader(gzReader), destDir, false)
}

// ExtractTarFromReader extracts an uncompressed tar stream directly from a reader
func ExtractTarFromReader(r io.Reader, destDir string) error {
	return extractTarReader(tar.NewReader(r), destDir, false)
}

// ExtractPortableTarGzFromReader extracts a remote archive while mapping all
// components to portable local names before any filesystem path is opened.
func ExtractPortableTarGzFromReader(r io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()
	return extractTarReader(tar.NewReader(gzReader), destDir, true)
}

// ExtractPortableTarFromReader is the uncompressed remote-archive variant.
func ExtractPortableTarFromReader(r io.Reader, destDir string) error {
	return extractTarReader(tar.NewReader(r), destDir, true)
}

// WriteTarToWriter creates a tar archive of a local directory and streams it to a writer.
// Used for streaming uploads over SSH stdin.
func WriteTarToWriter(sourceDir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	sourceDir = filepath.Clean(sourceDir)
	baseDir := filepath.Base(sourceDir)

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip files we can't read
		}

		// Build relative path: contents go into the tar root
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return nil
		}
		// Put files under the base directory name
		tarPath := filepath.ToSlash(filepath.Join(baseDir, relPath))
		if relPath == "." {
			tarPath = baseDir
		}

		// Handle symlinks
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return nil
			}
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return nil
		}
		header.Name = tarPath

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for '%s': %w", path, err)
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil // skip unreadable files
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})
}
