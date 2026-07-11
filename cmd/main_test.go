package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestCLIUsageErrorsAndHelpStreams(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		notStdout  []string
		notStderr  []string
	}{
		{
			name:       "help",
			args:       []string{"--help"},
			wantCode:   0,
			wantStdout: []string{"USAGE", "1..65535", "1..1024", "1..1048576", "transfer-timeout", "OS temp/coordinate", "key paths require -k=PATH"},
			notStderr:  []string{"Error:"},
		},
		{
			name:       "unknown flag",
			args:       []string{"--definitely-unknown"},
			wantCode:   2,
			wantStderr: []string{"unknown flag", "Usage: coordinate", "coordinate --help"},
			notStdout:  []string{"USAGE"},
		},
		{
			name:       "missing flag value",
			args:       []string{"--targets"},
			wantCode:   2,
			wantStderr: []string{"flag needs an argument", "Usage: coordinate"},
		},
		{
			name:       "missing required arguments",
			args:       nil,
			wantCode:   2,
			wantStderr: []string{"missing target", "Usage: coordinate"},
			notStdout:  []string{"USAGE"},
		},
		{
			name:       "mutually exclusive actions",
			args:       []string{"-t", "192.0.2.1", "-u", "root", "-p", "CLI_SECRET", "audit.sh", "-x", "hostname"},
			wantCode:   2,
			wantStderr: []string{"cannot specify both scripts and commands", "Usage: coordinate"},
			notStderr:  []string{"CLI_SECRET"},
		},
		{
			name:       "scheduled command requires interval",
			args:       []string{"-t", "192.0.2.1", "-u", "root", "-p", "CLI_SECRET", "--schedule", "true"},
			wantCode:   2,
			wantStderr: []string{"--interval must be"},
			notStderr:  []string{"CLI_SECRET"},
		},
		{
			name:       "scheduled command cannot combine with direct command",
			args:       []string{"-t", "192.0.2.1", "-u", "root", "-p", "CLI_SECRET", "--schedule", "true", "--interval", "5m", "-x", "hostname"},
			wantCode:   2,
			wantStderr: []string{"cannot combine scripts, --command, and --schedule"},
			notStderr:  []string{"CLI_SECRET"},
		},
		{
			name:       "invalid scheduler is rejected",
			args:       []string{"-t", "192.0.2.1", "-u", "root", "-p", "CLI_SECRET", "--schedule", "true", "--interval", "5m", "--scheduler", "at"},
			wantCode:   2,
			wantStderr: []string{"--scheduler must be one of auto, systemd, or cron"},
			notStderr:  []string{"CLI_SECRET"},
		},
		{
			name:       "ambiguous attached key path",
			args:       []string{"-k/tmp/id_ed25519"},
			wantCode:   2,
			wantStderr: []string{"bare -k uses ssh-agent", "key paths require -k=PATH"},
		},
		{
			name:       "config mode rejects manual authentication",
			args:       []string{"--use-config", "-k", "-x", "hostname"},
			wantCode:   2,
			wantStderr: []string{"--use-config cannot be combined", "Usage: coordinate"},
		},
		{
			name:       "config mode rejects bulk credential mutation",
			args:       []string{"--use-config", "--CO", "UNVERIFIED_SECRET", "-x", "hostname"},
			wantCode:   2,
			wantStderr: []string{"config-mutation flags", "Usage: coordinate"},
			notStderr:  []string{"UNVERIFIED_SECRET"},
		},
		{
			name:       "missing legacy create config helper fails early",
			args:       []string{"-t", "192.0.2.1", "-u", "root", "--create-config", "SECRET"},
			wantCode:   2,
			wantStderr: []string{"--create-config is unavailable", "--CO"},
			notStderr:  []string{"SECRET"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCoordinate(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout=%q\nstderr=%q", code, tt.wantCode, stdout, stderr)
			}
			assertStreamContains(t, "stdout", stdout, tt.wantStdout)
			assertStreamContains(t, "stderr", stderr, tt.wantStderr)
			assertStreamExcludes(t, "stdout", stdout, tt.notStdout)
			assertStreamExcludes(t, "stderr", stderr, tt.notStderr)
		})
	}
}

func TestCLIRejectsInvalidTargetsAndMissingScriptsBeforeConnecting(t *testing.T) {
	stdout, stderr, code := runCoordinate(t, "-t", "10.0.0.0/99", "-u", "root", "-p", "secret", "-x", "true")
	if code != 2 {
		t.Fatalf("invalid target exit = %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertStreamContains(t, "stderr", stderr, []string{"invalid --targets value"})

	stdout, stderr, code = runCoordinate(t, "-t", "127.0.0.1", "-u", "root", "-p", "secret", "missing-script.sh")
	if code != 2 {
		t.Fatalf("missing script exit = %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertStreamContains(t, "stderr", stderr, []string{"missing-script.sh", "unavailable"})
}

func TestCLINumericBoundariesFailBeforeExecution(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "zero port", args: []string{"--port=0"}, wantErr: "--port must be between 1 and 65535"},
		{name: "port too large", args: []string{"--port=65536"}, wantErr: "--port must be between 1 and 65535"},
		{name: "zero timeout", args: []string{"--timeout=0"}, wantErr: "--timeout must be greater than zero"},
		{name: "negative timeout", args: []string{"--timeout=-1"}, wantErr: "--timeout must be greater than zero"},
		{name: "zero per-host limit", args: []string{"--limit=0"}, wantErr: "--limit must be between 1 and 1024"},
		{name: "per-host limit too large", args: []string{"--limit=1025"}, wantErr: "--limit must be between 1 and 1024"},
		{name: "negative max hosts", args: []string{"--max-hosts=-1"}, wantErr: "--max-hosts must be between 0 and 4096"},
		{name: "max hosts too large", args: []string{"--max-hosts=4097"}, wantErr: "--max-hosts must be between 0 and 4096"},
		{name: "zero max targets", args: []string{"--max-targets=0"}, wantErr: "--max-targets must be between 1 and 1048576"},
		{name: "max targets too large", args: []string{"--max-targets=1048577"}, wantErr: "--max-targets must be between 1 and 1048576"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCoordinate(t, tt.args...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout, stderr)
			}
			assertStreamContains(t, "stderr", stderr, []string{tt.wantErr, "Usage: coordinate"})
			assertStreamExcludes(t, "stdout", stdout, []string{"Run summary"})
		})
	}
}

func TestCLISetupFailureStopsExecution(t *testing.T) {
	blockingFile := filepath.Join(t.TempDir(), "tmpdir-file")
	if err := os.WriteFile(blockingFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCoordinate(t,
		"--tmpdir="+blockingFile,
		"-t", "127.0.0.1",
		"-u", "root",
		"-p", "SETUP_FAILURE_SECRET",
		"-x", "hostname",
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout, stderr)
	}
	assertStreamContains(t, "stderr", stderr, []string{"prepare temporary directory", "not a directory"})
	assertStreamExcludes(t, "stdout", stdout, []string{"Run summary", "SETUP_FAILURE_SECRET"})
	assertStreamExcludes(t, "stderr", stderr, []string{"SETUP_FAILURE_SECRET"})
}

func TestZeroMaxHostsStillUsesAbsoluteSafetyCeiling(t *testing.T) {
	original := *globals.MaxHosts
	*globals.MaxHosts = 0
	t.Cleanup(func() { *globals.MaxHosts = original })

	limiter := newHostLimiter()
	if limiter.tokens == nil || cap(limiter.tokens) != globals.MaxHostConcurrency {
		t.Fatalf("zero max-host limiter capacity = %d, want %d", cap(limiter.tokens), globals.MaxHostConcurrency)
	}
}

func TestCLIOutputModesAndSecretRedaction(t *testing.T) {
	base := []string{"-t", "127.0.0.1", "-P", "1", "-u", "operator", "-p", "PASSWORD_SENTINEL", "-E", "ORDINARY_VALUE=ENV_SENTINEL", "-x", "hostname"}
	tests := []struct {
		name       string
		flags      []string
		wantStdout []string
		wantStderr []string
		notStdout  []string
		notStderr  []string
	}{
		{
			name:       "normal",
			wantStdout: []string{"Run summary", "hosts attempted=1", "failed=1"},
			wantStderr: []string{"ERROR"},
			notStderr:  []string{"DEBUG"},
		},
		{
			name:       "quiet",
			flags:      []string{"--quiet"},
			wantStderr: []string{"ERROR"},
			notStdout:  []string{"Run summary"},
			notStderr:  []string{"DEBUG", "WARN"},
		},
		{
			name:      "super quiet",
			flags:     []string{"--super-quiet"},
			notStdout: []string{"Run summary", "ERROR"},
			notStderr: []string{"ERROR", "DEBUG", "WARN"},
		},
		{
			name:       "errors only",
			flags:      []string{"--errors"},
			wantStderr: []string{"ERROR"},
			notStdout:  []string{"Run summary"},
			notStderr:  []string{"DEBUG", "WARN", "INFO"},
		},
		{
			name:       "debug",
			flags:      []string{"--debug"},
			wantStdout: []string{"Run summary", "hosts attempted=1", "failed=1"},
			wantStderr: []string{"DEBUG", "ERROR"},
		},
		{
			name:       "errors wins over debug",
			flags:      []string{"--errors", "--debug"},
			wantStderr: []string{"ERROR"},
			notStdout:  []string{"Run summary"},
			notStderr:  []string{"DEBUG", "WARN", "INFO"},
		},
		{
			name:      "super quiet wins over debug and quiet",
			flags:     []string{"--super-quiet", "--debug", "--quiet"},
			notStdout: []string{"Run summary", "ERROR"},
			notStderr: []string{"ERROR", "DEBUG", "WARN", "INFO"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(append([]string{}, base...), tt.flags...)
			stdout, stderr, code := runCoordinate(t, args...)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout, stderr)
			}
			assertStreamContains(t, "stdout", stdout, tt.wantStdout)
			assertStreamContains(t, "stderr", stderr, tt.wantStderr)
			assertStreamExcludes(t, "stdout", stdout, append(tt.notStdout, "PASSWORD_SENTINEL", "ENV_SENTINEL"))
			assertStreamExcludes(t, "stderr", stderr, append(tt.notStderr, "PASSWORD_SENTINEL", "ENV_SENTINEL"))
		})
	}
}

func TestCLIDebugOutputRedactsEnvironmentAndPasswordValues(t *testing.T) {
	stdout, stderr, code := runCoordinate(t,
		"-t", "127.0.0.1",
		"-u", "operator",
		"-p", "PASSWORD_VALUE_SENTINEL",
		"-E", "ORDINARY_VALUE=ENV_VALUE_SENTINEL",
		"-x", "hostname",
		"-P", "1",
		"--debug",
	)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout, stderr)
	}
	combined := stdout + stderr
	assertStreamContains(t, "combined", combined, []string{"operator", "127.0.0.1", "ORDINARY_VALUE", "Parsed 1 password candidates"})
	assertStreamExcludes(t, "combined", combined, []string{"PASSWORD_VALUE_SENTINEL", "ENV_VALUE_SENTINEL"})
}

func TestCLIAuthenticationFailureReturnsOneAndIsReportedOnce(t *testing.T) {
	stdout, stderr, code := runCoordinate(t,
		"-t", "127.0.0.1",
		"-P", "1",
		"-u", "root",
		"-p", "AUTH_FAILURE_SECRET",
		"-x", "hostname",
	)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout, stderr)
	}
	assertStreamContains(t, "stdout", stdout, []string{"Run summary", "hosts attempted=1", "authenticated=0", "failed=1", "authentication attempts=1"})
	if count := strings.Count(stderr, "Unable to connect to 127.0.0.1"); count != 1 {
		t.Fatalf("authentication failure appeared %d times, want once: %q", count, stderr)
	}
	assertStreamExcludes(t, "combined", stdout+stderr, []string{"AUTH_FAILURE_SECRET"})
}

func TestCLIMalformedConfigReadReturnsOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCoordinateInDir(t, dir, "--use-config", "-x", "hostname")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout, stderr)
	}
	assertStreamContains(t, "stderr", stderr, []string{"Configuration deployment failed", "config.json"})
	assertStreamExcludes(t, "stdout", stdout, []string{"Run summary"})
}

func TestCoordinateHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_COORDINATE_HELPER") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == -1 {
		os.Exit(99)
	}
	os.Args = append([]string{"coordinate"}, os.Args[separator+1:]...)
	main()
}

func runCoordinate(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runCoordinateInDir(t, t.TempDir(), args...)
}

func runCoordinateInDir(t *testing.T, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmdArgs := append([]string{"-test.run=^TestCoordinateHelperProcess$", "--"}, args...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "GO_WANT_COORDINATE_HELPER=1")
	cmd.Dir = dir
	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err := cmd.Run()
	code = 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run coordinate: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return stdoutBuffer.String(), stderrBuffer.String(), code
}

func assertStreamContains(t *testing.T, name, got string, values []string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(got, value) {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func assertStreamExcludes(t *testing.T, name, got string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(got, value) {
			t.Errorf("%s = %q, unexpectedly contains %q", name, got, value)
		}
	}
}
