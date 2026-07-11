package logger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestOutputModesRouteAndFilterMessages(t *testing.T) {
	tests := []struct {
		name       string
		mode       OutputMode
		wantStdout []string
		wantStderr []string
		notStdout  []string
		notStderr  []string
	}{
		{
			name:       "normal",
			mode:       OutputNormal,
			wantStdout: []string{"status", "payload-out", "info"},
			wantStderr: []string{"payload-err", "failure", "warning"},
			notStderr:  []string{"debug"},
		},
		{
			name:       "quiet",
			mode:       OutputQuiet,
			wantStdout: []string{"payload-out"},
			wantStderr: []string{"payload-err", "failure"},
			notStdout:  []string{"status", "info"},
			notStderr:  []string{"warning", "debug"},
		},
		{
			name:       "debug",
			mode:       OutputDebug,
			wantStdout: []string{"status", "payload-out", "info"},
			wantStderr: []string{"payload-err", "failure", "warning", "debug"},
		},
		{
			name:       "super quiet",
			mode:       OutputSuperQuiet,
			wantStdout: []string{"payload-out"},
			notStdout:  []string{"status", "info"},
			notStderr:  []string{"payload-err", "failure", "warning", "debug"},
		},
		{
			name:       "errors only",
			mode:       OutputErrorsOnly,
			wantStderr: []string{"payload-err", "failure"},
			notStdout:  []string{"status", "payload-out", "info"},
			notStderr:  []string{"warning", "debug"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			InitLoggerWithWriters(&stdout, &stderr)
			ActiveOutputMode = tt.mode
			*Outfile = ""

			instance := Instance{IP: "192.0.2.10", Username: "operator"}
			Status("status")
			Stdout(instance, "payload-out")
			Stderr(instance, "payload-err")
			Err("failure")
			Warning("warning")
			Info("info")
			Debug("debug")

			assertContainsAll(t, "stdout", stdout.String(), tt.wantStdout)
			assertContainsAll(t, "stderr", stderr.String(), tt.wantStderr)
			assertContainsNone(t, "stdout", stdout.String(), tt.notStdout)
			assertContainsNone(t, "stderr", stderr.String(), tt.notStderr)
		})
	}

	t.Cleanup(func() {
		ActiveOutputMode = OutputNormal
		InitLogger()
	})
}

func TestStdoutSavesExclusivelyBeneathOutput(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	InitLoggerWithWriters(&bytes.Buffer{}, &bytes.Buffer{})

	instance := Instance{IP: "192.0.2.1", Username: "root", ID: 1, Outfile: "host/result.txt"}
	if err := Stdout(instance, "first"); err != nil {
		t.Fatal(err)
	}
	if err := Stdout(instance, "second"); err == nil {
		t.Fatal("second output silently replaced the first")
	}
	got, err := os.ReadFile(filepath.Join(work, "output", "host", "result.txt"))
	if err != nil || string(got) != "first" {
		t.Fatalf("saved output=%q err=%v", got, err)
	}
}

func TestReserveOutputRejectsTraversalExistingAndSymlink(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	for index, path := range []string{"../escape", `..\\escape`, "/absolute", `C:\\absolute`} {
		if err := ReserveOutput(Instance{IP: "host", ID: index, Outfile: path}); err == nil {
			t.Errorf("ReserveOutput(%q) succeeded", path)
		}
	}
	if err := os.MkdirAll(filepath.Join("output", "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join("output", "safe", "existing.txt")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReserveOutput(Instance{IP: "host", ID: 20, Outfile: "safe/existing.txt"}); err == nil {
		t.Fatal("ReserveOutput accepted an existing file")
	}
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join("output", "linked")); err == nil {
			if err := ReserveOutput(Instance{IP: "host", ID: 21, Outfile: "linked/result.txt"}); err == nil {
				t.Fatal("ReserveOutput traversed a symlink component")
			}
		}
	}
}

func TestSummaryOmitsDirectCommandContents(t *testing.T) {
	const commandSecret = "HEADER_COMMAND_SECRET"
	summary := Summary(Instance{
		IP:       "192.0.2.30",
		Username: "operator",
		Hostname: "host-a",
		Script:   "command: curl --token " + commandSecret,
	})
	if strings.Contains(summary, commandSecret) || strings.Contains(summary, "curl") {
		t.Fatalf("Summary() = %q, want command contents omitted", summary)
	}
	if !strings.Contains(summary, "command") || !strings.Contains(summary, "192.0.2.30") {
		t.Fatalf("Summary() = %q, want safe command and host context", summary)
	}
}

func TestLoggerRedactsStructuredAndLabelledSecrets(t *testing.T) {
	const (
		instanceSecret = "INSTANCE_SENTINEL_PASSWORD"
		envSecret      = "ENV_SENTINEL_TOKEN"
		directSecret   = "DIRECT_SENTINEL_PASSWORD"
		ordinaryEnv    = "ORDINARY_ENV_SENTINEL"
	)

	var stdout, stderr bytes.Buffer
	InitLoggerWithWriters(&stdout, &stderr)
	ActiveOutputMode = OutputDebug
	SetSensitiveEnvironment([]string{"ORDINARY_VALUE=" + ordinaryEnv})
	Debug(
		Instance{IP: "192.0.2.20", Username: "admin", Password: instanceSecret},
		fmt.Sprintf("%+v", Instance{IP: "192.0.2.21", Username: "root", Password: instanceSecret + " with spaces"}),
		"API_TOKEN="+envSecret,
		"ORDINARY_VALUE="+ordinaryEnv+" command --arg",
		"password: "+directSecret,
	)

	got := stdout.String() + stderr.String()
	assertContainsNone(t, "combined log", got, []string{instanceSecret, envSecret, directSecret, ordinaryEnv})
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("combined log = %q, want redaction marker", got)
	}
	if !strings.Contains(got, "192.0.2.20") || !strings.Contains(got, "admin") {
		t.Fatalf("combined log = %q, want host and username context", got)
	}

	t.Cleanup(func() {
		ActiveOutputMode = OutputNormal
		SetSensitiveEnvironment(nil)
		InitLogger()
	})
}

func assertContainsAll(t *testing.T, streamName, got string, values []string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(got, value) {
			t.Errorf("%s = %q, want %q", streamName, got, value)
		}
	}
}

func assertContainsNone(t *testing.T, streamName, got string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(got, value) {
			t.Errorf("%s = %q, unexpectedly contains %q", streamName, got, value)
		}
	}
}
