package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/LanodonF/coordinate-foister/internal/logger"
)

const environmentFilePath = "env.json"

// ParseEnvironmentAssignments validates KEY=VALUE assignments without
// interpreting VALUE. In particular, spaces, quotes, shell metacharacters and
// semicolons remain part of the value exactly as supplied.
func ParseEnvironmentAssignments(raw []string) (map[string]string, error) {
	parsed := make(map[string]string, len(raw))
	for _, assignment := range raw {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok {
			// Do not echo the malformed operand: it may itself be a secret whose
			// operator accidentally omitted the equals sign.
			return nil, errors.New("environment assignment must use KEY=VALUE")
		}
		if err := validateEnvironmentEntry(key, value); err != nil {
			return nil, err
		}
		// As with a process environment, the last occurrence wins.
		parsed[key] = value
	}
	return parsed, nil
}

// ReadEnv merges the optional env.json file with command-line assignments.
// Command-line values take precedence. Missing env.json is not an error; an
// unreadable, malformed, or unsafe file is, so callers can stop before opening
// any SSH connections.
func ReadEnv(commandLine []string) ([]string, error) {
	return readEnvFile(environmentFilePath, commandLine)
}

func readEnvFile(path string, commandLine []string) ([]string, error) {
	logger.Debug(fmt.Sprintf("Attempting to read environment file %q...", path))

	merged := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read environment file %q: %w", path, err)
	}
	if err == nil {
		if err := json.Unmarshal(data, &merged); err != nil {
			return nil, fmt.Errorf("decode environment file %q: %w", path, err)
		}
		if merged == nil {
			return nil, fmt.Errorf("decode environment file %q: expected a JSON object", path)
		}
		for key, value := range merged {
			if err := validateEnvironmentEntry(key, value); err != nil {
				return nil, fmt.Errorf("environment file %q: %w", path, err)
			}
		}
		logger.Debug(fmt.Sprintf("Environment file %q read successfully.", path))
	} else {
		logger.Debug(fmt.Sprintf("Optional environment file %q not found.", path))
	}

	overrides, err := ParseEnvironmentAssignments(commandLine)
	if err != nil {
		return nil, fmt.Errorf("invalid --env value: %w", err)
	}
	for key, value := range overrides {
		merged[key] = value
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := make([]string, 0, len(keys))
	for _, key := range keys {
		assignments = append(assignments, key+"="+merged[key])
	}
	return assignments, nil
}

func validateEnvironmentEntry(key, value string) error {
	if !validEnvironmentKey(key) {
		return fmt.Errorf("invalid environment variable name %q (expected [A-Za-z_][A-Za-z0-9_]*)", key)
	}
	// POSIX process environments and shell variables cannot contain NUL. Fail
	// explicitly rather than silently truncating or changing the value.
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("environment variable %q contains a NUL byte", key)
	}
	return nil
}

func validEnvironmentKey(key string) bool {
	if key == "" || !asciiLetterOrUnderscore(key[0]) {
		return false
	}
	for i := 1; i < len(key); i++ {
		if !asciiLetterOrUnderscore(key[i]) && (key[i] < '0' || key[i] > '9') {
			return false
		}
	}
	return true
}

func asciiLetterOrUnderscore(char byte) bool {
	return char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
}
