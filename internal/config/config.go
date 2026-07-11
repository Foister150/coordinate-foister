package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/LanodonF/coordinate-foister/internal/logger"
)

const configFilePath = "config.json"

type ConfigEntry struct {
	IP       string
	Username string
	Password string
}

var configStore = struct {
	sync.RWMutex
	entries []ConfigEntry
}{}

// Snapshot returns a copy of the current entries. Callers can safely iterate
// over or modify the returned slice without racing with credential collection.
func Snapshot() []ConfigEntry {
	configStore.RLock()
	defer configStore.RUnlock()

	return append([]ConfigEntry{}, configStore.entries...)
}

// Count returns the number of entries currently held in memory.
func Count() int {
	configStore.RLock()
	defer configStore.RUnlock()

	return len(configStore.entries)
}

func replaceEntries(entries []ConfigEntry) {
	configStore.Lock()
	defer configStore.Unlock()

	configStore.entries = append([]ConfigEntry(nil), entries...)
}

func ReadConfig() error {
	logger.Debug("Attempting to read configuration file...")

	entries, err := readConfigFile(configFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			replaceEntries(nil)
			logger.Warning(fmt.Sprintf("Configuration file '%s' not found. Proceeding with empty configuration.", configFilePath))
			return nil
		}
		return fmt.Errorf("read %s: %w", configFilePath, err)
	}

	// Replace the shared state only after the entire file has been read and
	// decoded. A malformed or partially read file therefore cannot destroy the
	// last valid in-memory configuration.
	replaceEntries(entries)
	logger.Info(fmt.Sprintf("Successfully loaded configuration from '%s'. Entries: %d", configFilePath, len(entries)))
	return nil
}

func readConfigFile(path string) ([]ConfigEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []ConfigEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// UpdateEntry atomically inserts or replaces an entry. Updates for one IP are
// linearized by the store lock; as before, the last serialized update wins.
func UpdateEntry(entry ConfigEntry) {
	configStore.Lock()
	defer configStore.Unlock()

	for i, existing := range configStore.entries {
		if existing.IP == entry.IP {
			configStore.entries[i] = entry
			return
		}
	}
	configStore.entries = append(configStore.entries, entry)
}

func GetEntryByIP(ip string) ConfigEntry {
	configStore.RLock()
	defer configStore.RUnlock()

	for _, entry := range configStore.entries {
		if entry.IP == ip {
			return entry
		}
	}
	return ConfigEntry{}
}

func DeleteEntryByIP(ip string) {
	configStore.Lock()
	defer configStore.Unlock()

	for i, entry := range configStore.entries {
		if entry.IP == ip {
			copy(configStore.entries[i:], configStore.entries[i+1:])
			configStore.entries[len(configStore.entries)-1] = ConfigEntry{}
			configStore.entries = configStore.entries[:len(configStore.entries)-1]
			return
		}
	}
}

func SaveConfig() error {
	logger.Debug("Attempting to save configuration file...")

	if err := saveConfigFile(configFilePath, Snapshot()); err != nil {
		return fmt.Errorf("save %s: %w", configFilePath, err)
	}

	logger.Info(fmt.Sprintf("Successfully saved configuration to '%s'.", configFilePath))
	return nil
}

func saveConfigFile(path string, entries []ConfigEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}

	return writeConfigAtomically(path, data)
}

func writeConfigAtomically(path string, data []byte) error {
	return writeConfigAtomicallyWithRename(path, data, replaceFileAtomically)
}

func writeConfigAtomicallyWithRename(path string, data []byte, rename func(string, string) error) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	tempPath := tempFile.Name()
	tempOpen := true
	defer func() {
		if tempOpen {
			_ = tempFile.Close()
		}
		_ = os.Remove(tempPath)
	}()

	// CreateTemp currently uses 0600, but chmod makes the credential-file
	// contract explicit and protects it if that implementation ever changes.
	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary configuration: %w", err)
	}
	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		tempOpen = false
		return fmt.Errorf("close temporary configuration: %w", err)
	}
	tempOpen = false

	if err := rename(tempPath, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}
