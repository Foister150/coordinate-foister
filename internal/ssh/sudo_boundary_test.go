package ssh

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDiscardThroughBoundaryNeverExposesUnusedSudoPassword(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	const (
		password = "ssh-secret"
		marker   = "COORDINATE_STDIN_TEST_BOUNDARY"
	)
	payload := `if IFS= read -r inherited; then printf 'LEAK:%s' "$inherited"; else printf 'EOF'; fi`

	for _, test := range []struct {
		name  string
		stdin string
	}{
		{name: "sudo consumed password", stdin: marker + "\n"},
		{name: "cached or nopasswd sudo left password", stdin: sudoBoundaryInput(password, marker, "")},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", discardThroughBoundary(marker)+payload)
			cmd.Stdin = strings.NewReader(test.stdin)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("boundary shell failed: %v: %s", err, out)
			}
			if string(out) != "EOF" || strings.Contains(string(out), password) {
				t.Fatalf("payload inherited framed credential: %q", out)
			}
		})
	}
}

func TestDiscardThroughBoundaryPreservesPostBoundaryInput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	const marker = "COORDINATE_STDIN_TEST_BOUNDARY"
	cmd := exec.Command("sh", "-c", discardThroughBoundary(marker)+`IFS= read -r value; printf '%s' "$value"`)
	cmd.Stdin = strings.NewReader("unused-password\n" + marker + "\noperator-input\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("boundary shell failed: %v: %s", err, out)
	}
	if string(out) != "operator-input" {
		t.Fatalf("payload input = %q, want operator-input", out)
	}
}
