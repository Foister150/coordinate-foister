package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/LanodonF/coordinate-foister/internal/logger"
)

func resetConfigStore(t *testing.T) {
	t.Helper()
	previous := Snapshot()
	replaceEntries(nil)
	t.Cleanup(func() { replaceEntries(previous) })
}

func TestConcurrentUpdatesPreserveAllEntries(t *testing.T) {
	resetConfigStore(t)

	const entryCount = 500
	var wg sync.WaitGroup
	for i := 0; i < entryCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.0.2.%d", i)
			UpdateEntry(ConfigEntry{IP: ip, Username: "root", Password: fmt.Sprintf("password-%d", i)})
		}(i)
	}
	wg.Wait()

	if got := Count(); got != entryCount {
		t.Fatalf("Count() = %d, want %d", got, entryCount)
	}
	for i := 0; i < entryCount; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		entry := GetEntryByIP(ip)
		if entry.Password != fmt.Sprintf("password-%d", i) {
			t.Fatalf("entry %q was lost or corrupted: %+v", ip, entry)
		}
	}
}

func TestUpdateEntrySameIPUsesLastSerializedUpdate(t *testing.T) {
	resetConfigStore(t)

	UpdateEntry(ConfigEntry{IP: "192.0.2.1", Username: "first", Password: "old"})
	UpdateEntry(ConfigEntry{IP: "192.0.2.1", Username: "second", Password: "new"})

	want := ConfigEntry{IP: "192.0.2.1", Username: "second", Password: "new"}
	if got := GetEntryByIP(want.IP); got != want {
		t.Fatalf("GetEntryByIP() = %+v, want %+v", got, want)
	}
	if got := Count(); got != 1 {
		t.Fatalf("Count() = %d, want one entry for a repeated IP", got)
	}
}

func TestSnapshotDoesNotExposeMutableStore(t *testing.T) {
	resetConfigStore(t)
	UpdateEntry(ConfigEntry{IP: "192.0.2.1", Username: "root", Password: "original"})

	snapshot := Snapshot()
	snapshot[0].Password = "modified"
	_ = append(snapshot, ConfigEntry{IP: "192.0.2.2"})

	if got := GetEntryByIP("192.0.2.1").Password; got != "original" {
		t.Fatalf("mutating Snapshot() changed stored password to %q", got)
	}
	if got := Count(); got != 1 {
		t.Fatalf("mutating Snapshot() changed store length to %d", got)
	}
}

func TestLoadUpdateSavePreservesExistingEntries(t *testing.T) {
	resetConfigStore(t)
	path := filepath.Join(t.TempDir(), "config.json")
	original := []ConfigEntry{
		{IP: "192.0.2.10", Username: "admin", Password: "one"},
		{IP: "192.0.2.11", Username: "root", Password: "two"},
	}
	if err := saveConfigFile(path, original); err != nil {
		t.Fatalf("save original config: %v", err)
	}

	loaded, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	replaceEntries(loaded)
	added := ConfigEntry{IP: "192.0.2.12", Username: "operator", Password: "three"}
	UpdateEntry(added)
	if err := saveConfigFile(path, Snapshot()); err != nil {
		t.Fatalf("save updated config: %v", err)
	}

	got, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	want := append(append([]ConfigEntry{}, original...), added)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("updated entries = %+v, want %+v", got, want)
	}
}

func TestReadConfigErrorPreservesInMemoryEntries(t *testing.T) {
	resetConfigStore(t)
	logger.InitLogger()

	dir := t.TempDir()
	oldWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	want := []ConfigEntry{{IP: "192.0.2.20", Username: "root", Password: "preserve-me"}}
	replaceEntries(want)
	if err := os.WriteFile(configFilePath, []byte(`{"IP":`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ReadConfig(); err == nil {
		t.Fatal("ReadConfig() succeeded for malformed JSON")
	}
	if got := Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries after failed read = %+v, want %+v", got, want)
	}
}

func TestSaveConfigUsesMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfigFile(path, []ConfigEntry{{IP: "192.0.2.30"}}); err != nil {
		t.Fatalf("saveConfigFile(): %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", got)
	}
}

func TestAtomicRenameFailurePreservesPriorFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	before := []byte("previous valid configuration")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}

	renameErr := errors.New("injected rename failure")
	err := writeConfigAtomicallyWithRename(path, []byte("replacement"), func(oldPath, newPath string) error {
		if newPath != path {
			t.Errorf("rename destination = %q, want %q", newPath, path)
		}
		if _, err := os.Stat(oldPath); err != nil {
			t.Errorf("temporary file was not ready for rename: %v", err)
		}
		return renameErr
	})
	if !errors.Is(err, renameErr) {
		t.Fatalf("writeConfigAtomicallyWithRename() error = %v, want %v", err, renameErr)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("prior file changed after failed rename: got %q, want %q", after, before)
	}
	tempFiles, err := filepath.Glob(filepath.Join(dir, ".config.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", tempFiles)
	}
}
