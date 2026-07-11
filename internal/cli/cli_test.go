package cli

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestValidateNumericFlags(t *testing.T) {
	tests := []struct {
		name                             string
		port, timeout, perHost, maxHosts int
		maxTargets                       int64
		wantErr                          string
	}{
		{name: "minimum valid values", port: 1, timeout: 1, perHost: 1, maxHosts: 0, maxTargets: 1},
		{name: "maximum valid values", port: globals.MaxSSHPort, timeout: 1, perHost: globals.MaxPayloadConcurrency, maxHosts: globals.MaxHostConcurrency, maxTargets: globals.MaxTargetExpansion},
		{name: "zero port", port: 0, timeout: 1, perHost: 1, maxHosts: 1, maxTargets: 1, wantErr: "--port"},
		{name: "port over maximum", port: globals.MaxSSHPort + 1, timeout: 1, perHost: 1, maxHosts: 1, maxTargets: 1, wantErr: "--port"},
		{name: "zero timeout", port: 22, timeout: 0, perHost: 1, maxHosts: 1, maxTargets: 1, wantErr: "--timeout"},
		{name: "negative timeout", port: 22, timeout: -1, perHost: 1, maxHosts: 1, maxTargets: 1, wantErr: "--timeout"},
		{name: "zero per-host limit", port: 22, timeout: 1, perHost: 0, maxHosts: 1, maxTargets: 1, wantErr: "--limit"},
		{name: "per-host limit over ceiling", port: 22, timeout: 1, perHost: globals.MaxPayloadConcurrency + 1, maxHosts: 1, maxTargets: 1, wantErr: "--limit"},
		{name: "negative max hosts", port: 22, timeout: 1, perHost: 1, maxHosts: -1, maxTargets: 1, wantErr: "--max-hosts"},
		{name: "max hosts over ceiling", port: 22, timeout: 1, perHost: 1, maxHosts: globals.MaxHostConcurrency + 1, maxTargets: 1, wantErr: "--max-hosts"},
		{name: "zero max targets", port: 22, timeout: 1, perHost: 1, maxHosts: 1, maxTargets: 0, wantErr: "--max-targets"},
		{name: "max targets over ceiling", port: 22, timeout: 1, perHost: 1, maxHosts: 1, maxTargets: globals.MaxTargetExpansion + 1, wantErr: "--max-targets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNumericFlags(tt.port, tt.timeout, tt.perHost, tt.maxHosts, tt.maxTargets, 900)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateNumericFlags() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateNumericFlags() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNumericFlagsRejectsDurationOverflow(t *testing.T) {
	maxDurationSeconds := int64(math.MaxInt64) / int64(time.Second)
	// A 32-bit int cannot represent a value large enough to overflow a
	// duration expressed in seconds; its full positive range is safe.
	if int64(int(maxDurationSeconds+1)) != maxDurationSeconds+1 {
		t.Skip("int size cannot represent an overflowing timeout")
	}
	err := validateNumericFlags(22, int(maxDurationSeconds+1), 1, 1, 1, 900)
	if err == nil || !strings.Contains(err.Error(), "--timeout is too large") {
		t.Fatalf("validateNumericFlags() error = %v, want timeout overflow error", err)
	}
}

func TestValidateTransferTimeout(t *testing.T) {
	for _, tt := range []struct {
		name    string
		seconds int
		want    string
	}{
		{name: "minimum", seconds: 1},
		{name: "maximum", seconds: globals.MaxTransferTimeout},
		{name: "zero", seconds: 0, want: "greater than zero"},
		{name: "negative", seconds: -1, want: "greater than zero"},
		{name: "over ceiling", seconds: globals.MaxTransferTimeout + 1, want: "between 1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNumericFlags(22, 30, 3, 100, 65_536, tt.seconds)
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateTransferTimeoutRejectsDurationOverflow(t *testing.T) {
	maxDurationSeconds := int64(math.MaxInt64) / int64(time.Second)
	if int64(int(maxDurationSeconds+1)) != maxDurationSeconds+1 {
		t.Skip("int size cannot represent an overflowing timeout")
	}
	err := validateNumericFlags(22, 30, 3, 100, 65_536, int(maxDurationSeconds+1))
	if err == nil || !strings.Contains(err.Error(), "--transfer-timeout is too large") {
		t.Fatalf("error = %v, want transfer timeout overflow error", err)
	}
}

func TestParseScheduleInterval(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  time.Duration
		valid bool
	}{
		{value: "1m", want: time.Minute, valid: true},
		{value: "15m", want: 15 * time.Minute, valid: true},
		{value: "6h", want: 6 * time.Hour, valid: true},
		{value: "7m", want: 7 * time.Minute, valid: true},
		{value: "90m", want: 90 * time.Minute, valid: true},
		{value: "30s", want: 30 * time.Second, valid: true},
		{value: "500ms"},
		{value: "0s"},
		{value: "not-a-duration"},
	} {
		t.Run(tt.value, func(t *testing.T) {
			got, err := parseScheduleInterval(tt.value)
			if tt.valid {
				if err != nil || got != tt.want {
					t.Fatalf("parseScheduleInterval(%q) = %v, %v; want %v, nil", tt.value, got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseScheduleInterval(%q) = %v, nil; want error", tt.value, got)
			}
		})
	}
}

func TestValidateLocalInputs(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script.sh")
	upload := filepath.Join(dir, "upload")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upload, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalInputs([]string{script}, []string{upload + ";/tmp/upload"}); err != nil {
		t.Fatalf("valid local inputs rejected: %v", err)
	}
	if err := validateLocalInputs([]string{filepath.Join(dir, "missing.sh")}, nil); err == nil {
		t.Fatal("missing script accepted")
	}
	if err := validateLocalInputs([]string{dir}, nil); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("script directory error = %v", err)
	}
	if err := validateLocalInputs(nil, []string{filepath.Join(dir, "missing") + ";/tmp/x"}); err == nil {
		t.Fatal("missing upload source accepted")
	}
	if err := validateLocalInputs(nil, []string{"malformed"}); err == nil {
		t.Fatal("malformed upload accepted")
	}
	if err := validateLocalInputs(nil, []string{os.DevNull + ";/tmp/device"}); err == nil {
		t.Fatal("device upload source accepted")
	}
}

func TestValidateLegacyHelperFlagsRejectsNoOps(t *testing.T) {
	for _, name := range []string{"ignore-users", "all-pass", "callbacks"} {
		t.Run(name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			flags.String("ignore-users", "", "")
			flags.String("all-pass", "", "")
			flags.String("callbacks", "", "")
			if err := flags.Set(name, "value"); err != nil {
				t.Fatal(err)
			}
			if err := validateLegacyHelperFlags(flags); err == nil || !strings.Contains(err.Error(), "unavailable") {
				t.Fatalf("error = %v, want unavailable", err)
			}
		})
	}
}

func TestEnsurePrivateDirCreatesNestedOwnerOnlyDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "coordinate")
	if err := ensurePrivateDir(dir, false); err != nil {
		t.Fatalf("ensurePrivateDir() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("created path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory mode = %04o, want 0700", info.Mode().Perm())
	}
}

func TestEnsurePrivateDirRejectsFileAndSharedExplicitDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(file, false); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("ensurePrivateDir(file) error = %v, want not-a-directory error", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(shared, false); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("ensurePrivateDir(shared) error = %v, want permissions error", err)
	}
}

func TestEnsurePrivateDirRejectsSymlinkRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "coordinate-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for _, hardenExisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("harden_existing_%t", hardenExisting), func(t *testing.T) {
			err := ensurePrivateDir(link, hardenExisting)
			if err == nil || !strings.Contains(err.Error(), "symbolic link") {
				t.Fatalf("ensurePrivateDir(symlink, %t) error = %v, want symlink rejection", hardenExisting, err)
			}
		})
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("symlink target mode = %04o, want unchanged 0755", info.Mode().Perm())
		}
	}
}

func TestNormalizeOptionalKeyArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		wantErr string
	}{
		{
			name: "bare short key leaves script positional",
			args: []string{"-k", "~/.ssh/id_ed25519", "-x", "hostname"},
			want: []string{"-k", "~/.ssh/id_ed25519", "-x", "hostname"},
		},
		{
			name: "bare long key leaves script positional",
			args: []string{"--key", "/tmp/key", "-x", "hostname"},
			want: []string{"--key", "/tmp/key", "-x", "hostname"},
		},
		{
			name: "short key without path",
			args: []string{"-k", "-x", "hostname"},
			want: []string{"-k", "-x", "hostname"},
		},
		{
			name:    "ambiguous attached short key path",
			args:    []string{"-k/tmp/key"},
			wantErr: "key paths require -k=PATH",
		},
		{
			name: "explicit key assignment",
			args: []string{"-k=/tmp/key", "--key=/tmp/other"},
			want: []string{"-k=/tmp/key", "--key=/tmp/other"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeOptionalKeyArgs(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeOptionalKeyArgs() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeOptionalKeyArgs() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeOptionalKeyArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBareKeyFlagKeepsFollowingScriptPositional(t *testing.T) {
	args, err := normalizeOptionalKeyArgs([]string{"-k", "audit.sh"})
	if err != nil {
		t.Fatalf("normalizeOptionalKeyArgs() error = %v", err)
	}

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetInterspersed(true)
	key := flags.StringP("key", "k", "", "")
	flags.Lookup("key").NoOptDefVal = globals.AgentKeyFlagValue
	if err := flags.Parse(args); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if *key != globals.AgentKeyFlagValue {
		t.Fatalf("key = %q, want ssh-agent marker", *key)
	}
	if got := flags.Args(); !reflect.DeepEqual(got, []string{"audit.sh"}) {
		t.Fatalf("positional args = %v, want [audit.sh]", got)
	}
}

func TestExplicitKeyPathsRequireEquals(t *testing.T) {
	for _, arg := range []string{"-k=-private-key", "--key=-private-key"} {
		t.Run(arg, func(t *testing.T) {
			args, err := normalizeOptionalKeyArgs([]string{arg, "audit.sh"})
			if err != nil {
				t.Fatalf("normalizeOptionalKeyArgs() error = %v", err)
			}

			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			key := flags.StringP("key", "k", "", "")
			flags.Lookup("key").NoOptDefVal = globals.AgentKeyFlagValue
			if err := flags.Parse(args); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if *key != "-private-key" {
				t.Fatalf("key = %q, want -private-key", *key)
			}
			if got := flags.Args(); !reflect.DeepEqual(got, []string{"audit.sh"}) {
				t.Fatalf("positional args = %v, want [audit.sh]", got)
			}
		})
	}
}
