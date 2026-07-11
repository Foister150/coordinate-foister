package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCronExpressionUsesPortableNumericLists(t *testing.T) {
	for _, tt := range []struct {
		interval time.Duration
		want     string
	}{
		{time.Minute, "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59 * * * *"},
		{15 * time.Minute, "0,15,30,45 * * * *"},
		{time.Hour, "0 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 * * *"},
		{6 * time.Hour, "0 0,6,12,18 * * *"},
	} {
		got, err := cronExpression(tt.interval)
		if err != nil || got != tt.want {
			t.Fatalf("cronExpression(%s) = %q, %v; want %q, nil", tt.interval, got, err, tt.want)
		}
	}
	if _, err := cronExpression(7 * time.Minute); err == nil {
		t.Fatal("cronExpression accepted a non-divisor interval")
	}
}

func TestScheduledInstallScriptKeepsCommandOutOfCrontabLine(t *testing.T) {
	command := "printf '100% done' # preserve cron-special percent"
	installer, err := scheduledInstallScript(command, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id := scheduledCommandID(command)
	if !strings.Contains(installer, "# coordinate:"+id) || !strings.Contains(installer, "0,5,10,15,20,25,30,35,40,45,50,55 * * * *") {
		t.Fatalf("installer missing managed cron entry: %s", installer)
	}
	if !strings.Contains(installer, "$HOME/.coordinate/"+id+".sh") {
		t.Fatalf("installer cron entry does not reference managed script: %s", installer)
	}
	if strings.Contains(installer[strings.LastIndex(installer, "printf '%s\\n'"):], "100% done") {
		t.Fatalf("command leaked into cron line: %s", installer)
	}
}

func TestSystemdInstallScriptUsesArbitraryInterval(t *testing.T) {
	command := "echo systemd-managed"
	installer := systemdInstallScript(command, 90*time.Minute)
	id := scheduledCommandID(command)
	for _, want := range []string{
		"/etc/coordinate/" + id + ".sh",
		"coordinate-" + id + ".service",
		"coordinate-" + id + ".timer",
		"OnUnitActiveSec=5400s",
		"systemctl daemon-reload",
		"systemctl restart coordinate-" + id + ".timer",
	} {
		if !strings.Contains(installer, want) {
			t.Fatalf("systemd installer missing %q: %s", want, installer)
		}
	}
}

func TestScheduledInstallScriptRunsWithTraditionalCrontabInterface(t *testing.T) {
	command := "printf 'scheduled value: %s\\n' ok"
	installer, err := scheduledInstallScript(command, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// This deliberately implements only the POSIX crontab -l / crontab FILE
	// interface used by the installer.
	crontab := "#!/bin/sh\nif [ \"$1\" = -l ]; then [ -f \"$HOME/crontab\" ] && cat \"$HOME/crontab\"; exit 0; fi\ncp \"$1\" \"$HOME/crontab\"\n"
	path := filepath.Join(bin, "crontab")
	if err := os.WriteFile(path, []byte(crontab), 0o700); err != nil {
		t.Fatal(err)
	}
	process := exec.Command("sh", "-c", installer)
	process.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":"+os.Getenv("PATH"))
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	process = exec.Command("sh", "-c", installer)
	process.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":"+os.Getenv("PATH"))
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("repeat installer failed: %v\n%s", err, output)
	}
	id := scheduledCommandID(command)
	script, err := os.ReadFile(filepath.Join(home, ".coordinate", id+".sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), command) {
		t.Fatalf("managed script does not contain command: %q", script)
	}
	cron, err := os.ReadFile(filepath.Join(home, "crontab"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(cron)
	if !strings.Contains(line, "0,15,30,45 * * * *") || !strings.Contains(line, "$HOME/.coordinate/"+id+".sh") {
		t.Fatalf("unexpected installed crontab: %q", line)
	}
	if strings.Contains(line, command) {
		t.Fatalf("command appeared directly in crontab: %q", line)
	}
	if count := strings.Count(line, "# coordinate:"+id); count != 1 {
		t.Fatalf("managed crontab entry count = %d, want 1: %q", count, line)
	}
}
