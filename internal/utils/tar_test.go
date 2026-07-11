package utils

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testTarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
}

func TestExtractTarFromReaderExtractsNestedFiles(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "output")
	archive := makeTestTar(t,
		testTarEntry{name: ".", typeflag: tar.TypeDir},
		testTarEntry{name: "nested", typeflag: tar.TypeDir},
		testTarEntry{name: "nested/first.txt", typeflag: tar.TypeReg, body: "first"},
		testTarEntry{name: "nested/deeper/second.txt", typeflag: byte(0), body: "second"},
	)

	if err := ExtractTarFromReader(bytes.NewReader(archive), dest); err != nil {
		t.Fatalf("ExtractTarFromReader() error = %v", err)
	}

	assertFileContents(t, filepath.Join(dest, "nested", "first.txt"), "first")
	assertFileContents(t, filepath.Join(dest, "nested", "deeper", "second.txt"), "second")
}

func TestExtractTarFromReaderRefusesExistingFile(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "result.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := makeTestTar(t, testTarEntry{name: "result.txt", typeflag: tar.TypeReg, body: "replace"})
	if err := ExtractTarFromReader(bytes.NewReader(archive), dest); err == nil {
		t.Fatal("ExtractTarFromReader overwrote an existing file")
	}
	assertFileContents(t, target, "keep")
}

func TestExtractPortableTarFromReaderMapsWindowsInvalidNamesBeforeCreate(t *testing.T) {
	dest := t.TempDir()
	archive := makeTestTar(t,
		testTarEntry{name: "bad:name", typeflag: tar.TypeDir},
		testTarEntry{name: "bad:name/CON", typeflag: tar.TypeReg, body: "portable"},
	)
	if err := ExtractPortableTarFromReader(bytes.NewReader(archive), dest); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 {
		t.Fatalf("portable root entries=%v err=%v", entries, err)
	}
	if strings.ContainsAny(entries[0].Name(), `:<>"|?*`) {
		t.Fatalf("portable root retained invalid characters: %q", entries[0].Name())
	}
	children, err := os.ReadDir(filepath.Join(dest, entries[0].Name()))
	if err != nil || len(children) != 1 || children[0].Name() == "CON" {
		t.Fatalf("portable children=%v err=%v", children, err)
	}
}

func TestExtractPortableTarFromReaderRejectsCaseFoldCollision(t *testing.T) {
	dest := t.TempDir()
	archive := makeTestTar(t,
		testTarEntry{name: "Foo", typeflag: tar.TypeReg, body: "first"},
		testTarEntry{name: "foo", typeflag: tar.TypeReg, body: "second"},
	)
	if err := ExtractPortableTarFromReader(bytes.NewReader(archive), dest); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("portable case-fold collision error = %v", err)
	}
}

func TestExtractTarFromReaderRejectsEscapingPaths(t *testing.T) {
	tests := []struct {
		name      string
		entryName func(root, dest string) string
	}{
		{
			name: "parent traversal",
			entryName: func(_, _ string) string {
				return "../../escaped.txt"
			},
		},
		{
			name: "sibling prefix bypass",
			entryName: func(_, _ string) string {
				return "../outside/escaped.txt"
			},
		},
		{
			name: "absolute path",
			entryName: func(root, _ string) string {
				return filepath.Join(root, "absolute-escaped.txt")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "out")
			outside := filepath.Join(root, "outside")
			if err := os.MkdirAll(outside, 0755); err != nil {
				t.Fatal(err)
			}

			entryName := tt.entryName(root, dest)
			escapedTarget := filepath.Clean(filepath.Join(dest, filepath.FromSlash(entryName)))
			if filepath.IsAbs(filepath.FromSlash(entryName)) {
				escapedTarget = filepath.Clean(filepath.FromSlash(entryName))
			}
			archive := makeTestTar(t, testTarEntry{name: entryName, typeflag: tar.TypeReg, body: "owned"})
			err := ExtractTarFromReader(bytes.NewReader(archive), dest)
			if err == nil {
				t.Fatal("ExtractTarFromReader() error = nil, want unsafe-path error")
			}

			for _, candidate := range []string{
				escapedTarget,
				filepath.Join(root, "escaped.txt"),
				filepath.Join(outside, "escaped.txt"),
				filepath.Join(root, "absolute-escaped.txt"),
			} {
				assertPathDoesNotExist(t, candidate)
			}
		})
	}
}

func TestExtractTarFromReaderRejectsLinks(t *testing.T) {
	tests := []struct {
		name    string
		entries []testTarEntry
	}{
		{
			name: "escaping symlink followed by file",
			entries: []testTarEntry{
				{name: "redirect", typeflag: tar.TypeSymlink, linkname: "../outside"},
				{name: "redirect/escaped.txt", typeflag: tar.TypeReg, body: "owned"},
			},
		},
		{
			name: "symlink chain",
			entries: []testTarEntry{
				{name: "first", typeflag: tar.TypeSymlink, linkname: "second"},
				{name: "second", typeflag: tar.TypeSymlink, linkname: "../outside"},
				{name: "first/escaped.txt", typeflag: tar.TypeReg, body: "owned"},
			},
		},
		{
			name: "escaping hard link",
			entries: []testTarEntry{
				{name: "hard-link", typeflag: tar.TypeLink, linkname: "../outside/source.txt"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "out")
			outside := filepath.Join(root, "outside")
			if err := os.MkdirAll(outside, 0755); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(outside, "source.txt")
			if err := os.WriteFile(source, []byte("original"), 0644); err != nil {
				t.Fatal(err)
			}

			err := ExtractTarFromReader(bytes.NewReader(makeTestTar(t, tt.entries...)), dest)
			if err == nil {
				t.Fatal("ExtractTarFromReader() error = nil, want unsupported-link error")
			}
			if !strings.Contains(err.Error(), "unsupported link") {
				t.Fatalf("ExtractTarFromReader() error = %q, want unsupported-link context", err)
			}
			assertPathDoesNotExist(t, filepath.Join(outside, "escaped.txt"))
			assertFileContents(t, source, "original")
		})
	}
}

func TestExtractTarFromReaderDoesNotFollowExistingSymlink(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "out")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "redirect")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	archive := makeTestTar(t, testTarEntry{
		name:     "redirect/escaped.txt",
		typeflag: tar.TypeReg,
		body:     "owned",
	})
	err := ExtractTarFromReader(bytes.NewReader(archive), dest)
	if err == nil {
		t.Fatal("ExtractTarFromReader() error = nil, want symlink-component error")
	}
	assertPathDoesNotExist(t, filepath.Join(outside, "escaped.txt"))
}

func TestExtractTarFromReaderRejectsSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	realDest := filepath.Join(root, "real-destination")
	if err := os.Mkdir(realDest, 0755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "destination")
	if err := os.Symlink(realDest, dest); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	archive := makeTestTar(t, testTarEntry{name: "escaped.txt", typeflag: tar.TypeReg, body: "owned"})
	if err := ExtractTarFromReader(bytes.NewReader(archive), dest); err == nil {
		t.Fatal("ExtractTarFromReader() error = nil, want symlink-destination error")
	}
	assertPathDoesNotExist(t, filepath.Join(realDest, "escaped.txt"))
}

func TestExtractionTargetRejectsEmptyName(t *testing.T) {
	if _, err := extractionTarget(t.TempDir(), ""); err == nil {
		t.Fatal("extractionTarget() error = nil, want empty-name error")
	}
}

func TestExtractTarFromReaderRejectsUnsupportedEntryTypes(t *testing.T) {
	archive := makeTestTar(t, testTarEntry{name: "device", typeflag: tar.TypeChar})
	err := ExtractTarFromReader(bytes.NewReader(archive), t.TempDir())
	if err == nil {
		t.Fatal("ExtractTarFromReader() error = nil, want unsupported-type error")
	}
	if !strings.Contains(err.Error(), "unsupported tar entry type") {
		t.Fatalf("ExtractTarFromReader() error = %q, want unsupported-type context", err)
	}
}

func TestExtractTarFromReaderPropagatesTruncatedFileError(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "partial.txt", Mode: 0644, Size: 128, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not close the writer: that would pad the incomplete body.

	dest := t.TempDir()
	err := ExtractTarFromReader(bytes.NewReader(archive.Bytes()), dest)
	if err == nil {
		t.Fatal("ExtractTarFromReader() error = nil, want truncated archive error")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("ExtractTarFromReader() error = %v, want unexpected EOF", err)
	}
	assertPathDoesNotExist(t, filepath.Join(dest, "partial.txt"))
}

func makeTestTar(t *testing.T, entries ...testTarEntry) []byte {
	t.Helper()

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0644,
			Size:     int64(len(entry.body)),
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
		}
		if entry.typeflag == tar.TypeDir {
			header.Mode = 0755
			header.Size = 0
		}
		if entry.typeflag == tar.TypeSymlink || entry.typeflag == tar.TypeLink {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%q): %v", entry.name, err)
		}
		if entry.body != "" {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatalf("Write(%q): %v", entry.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	return archive.Bytes()
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("ReadFile(%q) = %q, want %q", path, got, want)
	}
}

func assertPathDoesNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Lstat(%q) error = %v, want not-exist", path, err)
	}
}
