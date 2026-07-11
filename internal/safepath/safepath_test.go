package safepath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestSanitizeComponentPortableAndDeterministic(t *testing.T) {
	tests := []string{
		"../../outside",
		`host\\share`,
		"2001:db8::10",
		"bad\x00\r\nname",
		"CON",
		"LPT1.txt",
		"name?.sh",
		".",
		"..",
	}
	for _, input := range tests {
		got := SanitizeComponent(input)
		if got == "" || got == "." || got == ".." {
			t.Errorf("SanitizeComponent(%q) = %q", input, got)
		}
		if strings.ContainsAny(got, "/\\<>:\"|?*\x00\r\n") {
			t.Errorf("SanitizeComponent(%q) = %q, not portable", input, got)
		}
		if again := SanitizeComponent(input); again != got {
			t.Errorf("SanitizeComponent(%q) changed from %q to %q", input, got, again)
		}
	}
	if SanitizeComponent("a/b") == SanitizeComponent(`a\\b`) {
		t.Fatal("distinct unsafe values collided after sanitization")
	}
	if SanitizeComponent("foo.") == SanitizeComponent("foo") {
		t.Fatal("trimmed unsafe value collided with safe value")
	}
	if got := SanitizeComponent(".hidden"); got != ".hidden" {
		t.Fatalf("portable dotfile changed to %q", got)
	}
	if got := SanitizeComponent("web-01.example"); got != "web-01.example" {
		t.Fatalf("safe hostname changed to %q", got)
	}
}

func TestResolveBelowRejectsPortableTraversal(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{"../escape", `..\\escape`, "/absolute", `C:\\absolute`, `\\\\server\\share`, "safe/../../escape", "safe/CON/file"} {
		if got, err := ResolveBelow(root, relative); err == nil {
			t.Errorf("ResolveBelow(%q) = %q, want error", relative, got)
		}
	}
	got, err := ResolveBelow(root, "host/payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "host", "payload.txt")
	if got != want {
		t.Fatalf("ResolveBelow() = %q, want %q", got, want)
	}
}

func TestEnsureDirBelowRejectsSymlinkComponents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, err := EnsureDirBelow(root, "linked/escape", 0o700); err == nil {
		t.Fatal("EnsureDirBelow traversed a symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatalf("outside path created through symlink: %v", err)
	}
}

func TestAtomicWriteExclusiveNeverOverwritesOrCollides(t *testing.T) {
	root := t.TempDir()
	if err := AtomicWriteExclusive(root, "host/result.txt", []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteExclusive(root, "host/result.txt", []byte("second"), 0o600); err == nil {
		t.Fatal("second write unexpectedly overwrote the first")
	}
	got, err := os.ReadFile(filepath.Join(root, "host", "result.txt"))
	if err != nil || string(got) != "first" {
		t.Fatalf("saved content = %q, err=%v", got, err)
	}

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- AtomicWriteExclusive(root, "race.txt", []byte("complete"), 0o600)
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent writers = %d, want 1", successes)
	}
}
