package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvironmentAssignmentsPreservesValues(t *testing.T) {
	raw := []string{
		"EMPTY=",
		"SPECIAL= spaces ' \" $HOME `whoami`; two;three\nlast ",
		"UNDER_SCORE_9=value=with=equals",
		"DUPLICATE=first",
		"DUPLICATE=last",
	}
	got, err := ParseEnvironmentAssignments(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range raw {
		key, value, _ := strings.Cut(assignment, "=")
		if key == "DUPLICATE" && value == "first" {
			continue
		}
		if got[key] != value {
			t.Errorf("value for %s = %q, want exact %q", key, got[key], value)
		}
	}
}

func TestParseEnvironmentAssignmentsDoesNotDiscloseMalformedOperand(t *testing.T) {
	const secret = "highly-sensitive-value"
	_, err := ParseEnvironmentAssignments([]string{secret})
	if err == nil {
		t.Fatal("ParseEnvironmentAssignments() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed malformed environment operand: %v", err)
	}
}

func TestParseEnvironmentAssignmentsRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{
		"NO_EQUALS",
		"=empty-key",
		"9START=digit",
		"HAS-DASH=value",
		"HAS SPACE=value",
		"A;touch /tmp/injected=value",
		"UNICODÉ=value",
		"NUL=before\x00after",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseEnvironmentAssignments([]string{value}); err == nil {
				t.Fatalf("ParseEnvironmentAssignments(%q) unexpectedly succeeded", value)
			}
		})
	}
}

func TestReadEnvFileCommandLineOverridesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.json")
	fileValue := `{"FILE_ONLY":"from file","OVERRIDE":"file","SPECIAL":"a; b '$HOME` + "`uname`" + `"}`
	if err := os.WriteFile(path, []byte(fileValue), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readEnvFile(path, []string{"OVERRIDE=command line", "CLI_ONLY=$VALUE;still value"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CLI_ONLY=$VALUE;still value",
		"FILE_ONLY=from file",
		"OVERRIDE=command line",
		"SPECIAL=a; b '$HOME`uname`",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readEnvFile() = %#v, want %#v", got, want)
	}
}

func TestReadEnvFileErrorsBeforeUse(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "malformed json", json: `{"A":`},
		{name: "null instead of object", json: `null`},
		{name: "invalid file key", json: `{"BAD-KEY":"value"}`},
		{name: "nul file value", json: `{"KEY":"before\u0000after"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "env.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readEnvFile(path, nil); err == nil {
				t.Fatal("readEnvFile() unexpectedly succeeded")
			}
		})
	}
}

func TestReadEnvFileAllowsMissingOptionalFile(t *testing.T) {
	got, err := readEnvFile(filepath.Join(t.TempDir(), "missing.json"), []string{"SAFE=value"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"SAFE=value"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("readEnvFile() = %#v, want %#v", got, want)
	}
}
