package ssh

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

func TestShQuote(t *testing.T) {
	cases := map[string]string{
		"abc":       "'abc'",
		"":          "''",
		"a b c":     "'a b c'",
		"a'b":       `'a'\''b'`,
		"rm -rf /'": `'rm -rf /'\'''`,
		"$(whoami)": "'$(whoami)'",
	}
	for in, want := range cases {
		if got := shQuote(in); got != want {
			t.Errorf("shQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShWrap(t *testing.T) {
	if got, want := shWrap("echo hi"), "sh -c 'echo hi'"; got != want {
		t.Errorf("shWrap() = %q, want %q", got, want)
	}
	// A command containing single quotes must remain a single, safe argument.
	if got := shWrap("echo 'hi'"); got != `sh -c 'echo '\''hi'\'''` {
		t.Errorf("shWrap with quotes = %q", got)
	}
}

func TestPrepareScriptReadsAndNormalizesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\r\necho hi\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := prepareScript(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "#!/bin/sh\necho hi\n"; first != want {
		t.Fatalf("prepareScript() = %q, want %q", first, want)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second, err := prepareScript(path)
	if err != nil {
		t.Fatalf("cached prepareScript() re-read the removed file: %v", err)
	}
	if second != first {
		t.Fatalf("cached prepareScript() = %q, want %q", second, first)
	}
}

func TestEnvPrefix(t *testing.T) {
	orig := EnvironCmds
	defer func() { EnvironCmds = orig }()

	EnvironCmds = nil
	if got := envPrefix(); got != "" {
		t.Errorf("envPrefix() with no env = %q, want empty", got)
	}

	EnvironCmds = []string{"FOO=bar", "BAZ=qux"}
	if got, want := envPrefix(), "export 'FOO=bar' || exit 125; export 'BAZ=qux' || exit 125; "; got != want {
		t.Errorf("envPrefix() = %q, want %q", got, want)
	}
}

func TestEnvPrefixPreservesSpecialValuesWithoutShellEvaluation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote payload is a POSIX shell command")
	}
	orig := EnvironCmds
	defer func() { EnvironCmds = orig }()

	marker := filepath.Join(t.TempDir(), "injected")
	value := " spaces ' \" $HOME $(touch " + marker + ") `touch " + marker + "` ;semi\nlast "
	EnvironCmds = []string{"SPECIAL=" + value}
	cmd := exec.Command("sh", "-c", envPrefix()+`true; printf '%s' "$SPECIAL"`)
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("safe environment command failed: %v", err)
	}
	if string(got) != value {
		t.Fatalf("environment value = %q, want exact %q", got, value)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("shell syntax in environment value was evaluated: %v", err)
	}
}

func TestIsRootID(t *testing.T) {
	if !isRootID([]byte("0\n")) {
		t.Error("isRootID should accept plain 0")
	}
	if !isRootID([]byte("[sudo] password for user:\n0\n")) {
		t.Error("isRootID should accept 0 after a sudo prompt line")
	}
	if isRootID([]byte("1000\n")) {
		t.Error("isRootID should reject a non-root uid")
	}
	if isRootID([]byte("")) {
		t.Error("isRootID should reject empty output")
	}
}

func TestDecideSudo(t *testing.T) {
	tests := []struct {
		name                string
		username            string
		requested           bool
		escalationSucceeded bool
		want                sudoDecision
	}{
		{name: "root needs no wrapper", username: "root", requested: true, want: sudoNotNeeded},
		{name: "not requested", username: "admin", want: sudoNotNeeded},
		{name: "available", username: "admin", requested: true, escalationSucceeded: true, want: sudoAvailable},
		{name: "explicit failure", username: "admin", requested: true, want: sudoFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideSudo(tt.username, tt.requested, tt.escalationSucceeded); got != tt.want {
				t.Fatalf("decideSudo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRemoteScriptDir(t *testing.T) {
	for _, valid := range []string{"/tmp/coordinate.abc123\n", "login banner\n/tmp/coordinate.XYZ_123\n"} {
		if _, err := parseRemoteScriptDir([]byte(valid)); err != nil {
			t.Errorf("parseRemoteScriptDir(%q) unexpected error: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "/tmp/not-coordinate.abc", "/tmp/coordinate.foo/bar", "/tmp/coordinate."} {
		if _, err := parseRemoteScriptDir([]byte(invalid)); err == nil {
			t.Errorf("parseRemoteScriptDir(%q) accepted an unsafe path", invalid)
		}
	}
}

func TestRootOwnedScriptPayloadRefusesPrecreatedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote payload is a POSIX shell command")
	}
	origEnv := EnvironCmds
	EnvironCmds = nil
	defer func() { EnvironCmds = origEnv }()

	parent := t.TempDir()
	rootDir := filepath.Join(parent, "coordinate-root.test")
	attackerMarker := filepath.Join(parent, "attacker-ran")
	if err := os.Mkdir(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	attacker := "#!/bin/sh\nprintf attacker > " + shQuote(attackerMarker) + "\n"
	if err := os.WriteFile(filepath.Join(rootDir, "payload"), []byte(attacker), 0o700); err != nil {
		t.Fatal(err)
	}
	intendedMarker := filepath.Join(parent, "intended-ran")
	intended := "#!/bin/sh\nprintf intended > " + shQuote(intendedMarker) + "\n"
	cmd := exec.Command("sh", "-c", rootOwnedScriptPayload(rootDir))
	cmd.Stdin = strings.NewReader(intended)
	if err := cmd.Run(); err == nil {
		t.Fatal("precreated same-UID payload path was accepted")
	}
	if _, err := os.Stat(attackerMarker); !os.IsNotExist(err) {
		t.Fatal("precreated attacker payload executed")
	}
	if _, err := os.Stat(intendedMarker); !os.IsNotExist(err) {
		t.Fatal("intended bytes were written through an unsafe precreated directory")
	}
}

func TestRootOwnedScriptPayloadExecutesStreamedBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote payload is a POSIX shell command")
	}
	origEnv := EnvironCmds
	EnvironCmds = nil
	defer func() { EnvironCmds = origEnv }()
	parent := t.TempDir()
	rootDir := filepath.Join(parent, "coordinate-root.test")
	marker := filepath.Join(parent, "ran")
	script := "#!/bin/sh\nprintf intended > " + shQuote(marker) + "\n"
	cmd := exec.Command("sh", "-c", rootOwnedScriptPayload(rootDir))
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Chmod(rootDir, 0o700)
		t.Fatalf("streamed payload failed: %v: %s", err, out)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "intended" {
		t.Fatalf("streamed payload output=%q err=%v", got, err)
	}
	// Non-root test execution cannot traverse a mode-0500 directory to remove
	// its file through the trap on every platform; restore it for TempDir cleanup.
	if _, err := os.Stat(rootDir); err == nil {
		_ = os.Chmod(rootDir, 0o700)
	}
}

func TestPrivilegedScriptCommandUsesBoundary(t *testing.T) {
	command := privilegedScriptCommand("/tmp/coordinate-root.test", "BOUNDARY")
	for _, want := range []string{"sudo -S", "BOUNDARY", "cat >", "mkdir --"} {
		if !strings.Contains(command, want) {
			t.Errorf("privileged command missing %q: %s", want, command)
		}
	}
	if strings.Contains(command, "coordinate_pw") {
		t.Fatal("privileged command should not place the password in a shell variable or command line")
	}
}

func TestPrivilegedCleanupPayloadRejectsRecreatedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cleanup payload is POSIX shell")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "root-dir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := exec.Command("sh", "-c", privilegedCleanupPayload(link)).Run(); err == nil {
		t.Fatal("recreated symlink was accepted as successful cleanup")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("unsafe replacement was removed: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	if err := exec.Command("sh", "-c", privilegedCleanupPayload(missing)).Run(); err != nil {
		t.Fatalf("already absent directory should be successful: %v", err)
	}
}

func TestNormalizeScript(t *testing.T) {
	if got, want := normalizeScript("#!/bin/sh\r\necho hi\r\n"), "#!/bin/sh\necho hi\n"; got != want {
		t.Fatalf("normalizeScript() = %q, want %q", got, want)
	}
}

func TestHostLabel(t *testing.T) {
	if got := hostLabel(Instance{IP: "1.2.3.4"}); got != "1.2.3.4" {
		t.Errorf("hostLabel fallback = %q", got)
	}
	if got := hostLabel(Instance{IP: "1.2.3.4", Hostname: "web01"}); got != "web01" {
		t.Errorf("hostLabel = %q, want web01", got)
	}
}

func TestPackageInstallCommand(t *testing.T) {
	for _, mgr := range []string{"apt-get", "dnf", "yum", "zypper", "pacman", "apk", "pkg", "pkg_add"} {
		cmd := packageInstallCommand(mgr)
		if !strings.Contains(cmd, "rsync") {
			t.Errorf("packageInstallCommand(%q) = %q, expected it to install rsync", mgr, cmd)
		}
	}
	if got := packageInstallCommand("nope"); got != "" {
		t.Errorf("packageInstallCommand(unknown) = %q, want empty", got)
	}
	pacman := packageInstallCommand("pacman")
	if strings.Contains(pacman, "-Sy") || !strings.Contains(pacman, "--needed") {
		t.Errorf("pacman install must avoid partial upgrades, got %q", pacman)
	}
}

func TestParsePackageManager(t *testing.T) {
	if got := parsePackageManager([]byte("login banner\napt-get\n")); got != "apt-get" {
		t.Fatalf("parsePackageManager() = %q, want apt-get", got)
	}
	if got := parsePackageManager([]byte("malicious-manager\n")); got != "" {
		t.Fatalf("parsePackageManager() accepted %q", got)
	}
}

func TestInstallRsyncOnceConcurrent(t *testing.T) {
	var calls atomic.Int32
	install := func() error {
		calls.Add(1)
		return nil
	}
	key := "test-host-" + t.TempDir()
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := installRsyncOnce(key, install); err != nil {
				t.Errorf("installRsyncOnce() error = %v", err)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("installer called %d times, want once", got)
	}
}

func TestRsyncHost(t *testing.T) {
	if got := rsyncHost("192.168.1.5"); got != "192.168.1.5" {
		t.Errorf("rsyncHost(ipv4) = %q", got)
	}
	if got := rsyncHost("fe80::1"); got != "[fe80::1]" {
		t.Errorf("rsyncHost(ipv6) = %q, want bracketed", got)
	}
}

func TestRsyncArgsProtectOperands(t *testing.T) {
	args := rsyncArgs("ssh transport", "-leading source", "host:/path with * glob")
	separator := -1
	for idx, arg := range args {
		if arg == "--" {
			separator = idx
		}
	}
	if separator < 0 || separator+2 >= len(args) {
		t.Fatalf("rsync args missing operand separator: %q", args)
	}
	if args[separator+1] != "-leading source" || args[separator+2] != "host:/path with * glob" {
		t.Fatalf("rsync operands changed or misplaced: %q", args)
	}
	if !containsString(args, "--protect-args") {
		t.Fatalf("rsync args missing --protect-args: %q", args)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunRsyncPartialIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake rsync uses a POSIX script")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rsync")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho partial >&2\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	err := runRsync(Instance{Username: "admin", IP: "127.0.0.1"}, "/source", "admin@host:/dest")
	if err == nil || !strings.Contains(err.Error(), "partial transfer (exit 23") {
		t.Fatalf("runRsync() error = %v, want explicit partial-transfer failure", err)
	}
}

func TestLocalRsyncOperandIsAbsolute(t *testing.T) {
	got, err := localRsyncOperand("-leading:name")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) || strings.HasPrefix(got, "-") {
		t.Fatalf("localRsyncOperand() = %q, want unambiguous absolute path", got)
	}
}

func TestNormalizeRemoteDownloadRoot(t *testing.T) {
	for _, input := range []string{"/", "///", " / "} {
		got, err := normalizeRemoteDownloadPath(input)
		if err != nil || got != "/" {
			t.Errorf("normalizeRemoteDownloadPath(%q) = %q, %v; want /", input, got, err)
		}
	}
	if _, err := normalizeRemoteDownloadPath("   "); err == nil {
		t.Fatal("empty remote path was accepted")
	}
	if got, err := normalizeRemoteDownloadPath("/var/log/"); err != nil || got != "/var/log" {
		t.Fatalf("normal path = %q, %v", got, err)
	}
}

func TestRemoteDownloadValidationCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote validation is a POSIX shell command")
	}
	parent := t.TempDir()
	tree := filepath.Join(parent, "tree'; touch PWNED; #'")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "file"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func() (string, error) {
		cmd := exec.Command("sh", "-c", remoteDownloadValidationCommand(tree))
		cmd.Dir = parent
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := run(); err != nil || out != "" {
		t.Fatalf("safe tree validation output=%q err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "PWNED")); !os.IsNotExist(err) {
		t.Fatal("validation path was evaluated as shell syntax")
	}
	if err := os.Symlink(filepath.Join(tree, "file"), filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err != nil || out != "UNSAFE" {
		t.Fatalf("linked tree validation output=%q err=%v, want UNSAFE", out, err)
	}
}

func TestWriteAskpassHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX askpass helper is intentionally unavailable on native Windows")
	}
	path, cleanup, err := writeAskpassHelper()
	if err != nil {
		t.Fatalf("writeAskpassHelper() error = %v", err)
	}
	defer cleanup()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("askpass helper not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("askpass helper mode = %v, want 0700", info.Mode().Perm())
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read askpass helper: %v", err)
	}
	// The password itself must never be written into the helper — it is read
	// from the environment at runtime.
	if !strings.Contains(string(body), "COORD_ASKPASS_PW") {
		t.Errorf("askpass helper should read the password from the environment, got: %s", body)
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove askpass helper")
	}
}

func TestBuildRsyncTransportPassword(t *testing.T) {
	i := Instance{Username: "root", IP: "10.0.0.5", Password: "s3cr3t"}
	rsh, env, cleanup, err := buildRsyncTransport(i)
	if runtime.GOOS == "windows" {
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("native Windows password transport error = %v, want safe unsupported fallback", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("buildRsyncTransport() error = %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	for _, want := range []string{"ssh", "StrictHostKeyChecking=no", "PubkeyAuthentication=no", "PreferredAuthentications=password"} {
		if !strings.Contains(rsh, want) {
			t.Errorf("password-mode rsh missing %q: %s", want, rsh)
		}
	}
	var sawPW, sawAskpass bool
	for _, e := range env {
		if e == "COORD_ASKPASS_PW=s3cr3t" {
			sawPW = true
		}
		if strings.HasPrefix(e, "SSH_ASKPASS=") {
			sawAskpass = true
		}
	}
	if !sawPW {
		t.Error("password not injected into rsync env")
	}
	if !sawAskpass {
		t.Error("SSH_ASKPASS not set for password-mode rsync")
	}
}

func TestBuildRsyncTransportKeyMode(t *testing.T) {
	// No password → key/agent mode; must not create an askpass helper.
	i := Instance{Username: "admin", IP: "10.0.0.6"}
	rsh, env, cleanup, err := buildRsyncTransport(i)
	if err != nil {
		t.Fatalf("buildRsyncTransport() error = %v", err)
	}
	if cleanup != nil {
		t.Error("key mode should not allocate an askpass cleanup")
		cleanup()
	}
	if !strings.Contains(rsh, "PreferredAuthentications=publickey") {
		t.Errorf("key-mode rsh missing publickey preference: %s", rsh)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "COORD_ASKPASS_PW=") {
			t.Error("key mode must not set a password in the environment")
		}
	}
}

func TestBuildRsyncTransportQuotesKeyPath(t *testing.T) {
	origKey := *Key
	*Key = "/tmp/key with ' quote"
	defer func() { *Key = origKey }()

	rsh, _, cleanup, err := buildRsyncTransport(Instance{Username: "admin", IP: "10.0.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if !strings.Contains(rsh, shQuote(*Key)) {
		t.Fatalf("key path is not one safely quoted transport argument: %s", rsh)
	}
}

func TestStreamUploadFileCommandQuotesPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote command is POSIX shell")
	}
	dir := t.TempDir()
	remote := "target'; touch PWNED; #'"
	cmd := exec.Command("sh", "-c", streamUploadFileCommand(remote, "ignored", "644"))
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("contents")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("safe upload command failed: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "PWNED")); !os.IsNotExist(err) {
		t.Fatal("remote path was evaluated as shell syntax")
	}
	body, err := os.ReadFile(filepath.Join(dir, remote))
	if err != nil || string(body) != "contents" {
		t.Fatalf("quoted destination not written correctly: body=%q err=%v", body, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteUploadTarPropagatesWriterFailure(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeUploadTar(source, failingWriter{}); err == nil {
		t.Fatal("writeUploadTar silently accepted a writer failure")
	}
}

func TestReplaceDownloadedFileInstallsExclusively(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "partial")
	newPath := filepath.Join(dir, "final")
	if err := os.WriteFile(oldPath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceDownloadedFile(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(newPath)
	if err != nil || string(got) != "new" {
		t.Fatalf("replaced content=%q err=%v", got, err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("source temporary file still exists after replacement")
	}

	secondTemp := filepath.Join(dir, "second-partial")
	if err := os.WriteFile(secondTemp, []byte("overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceDownloadedFile(secondTemp, newPath); err == nil {
		t.Fatal("existing destination was overwritten")
	}
	got, err = os.ReadFile(newPath)
	if err != nil || string(got) != "new" {
		t.Fatalf("content changed after rejected overwrite: %q err=%v", got, err)
	}
}

func TestHardenDownloadedArtifact(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifact")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o777); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "nested", "file")
	if err := os.WriteFile(file, []byte("data"), 0o777); err != nil {
		t.Fatal(err)
	}
	// Ensure the test starts permissive even under a restrictive process umask.
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "nested"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := hardenDownloadedArtifact(root); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{root, filepath.Join(root, "nested")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("stat directory %s: %v", dir, err)
			continue
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("directory %s mode=%v, want 0700", dir, info.Mode().Perm())
		}
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%v, want 0600", info.Mode().Perm())
	}
}

func localReadFS() remoteReadFS {
	return remoteReadFS{
		lstat: os.Lstat,
		readDir: func(path string) ([]os.FileInfo, error) {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}
			infos := make([]os.FileInfo, 0, len(entries))
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					return nil, err
				}
				infos = append(infos, info)
			}
			return infos, nil
		},
		open: func(path string) (io.ReadCloser, error) { return os.Open(path) },
	}
}

func TestDownloadSFTPTreeRecursive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote test paths use POSIX joining")
	}
	sourceParent := t.TempDir()
	source := filepath.Join(sourceParent, "source tree")
	if err := os.MkdirAll(filepath.Join(source, "nested", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "deep", "file.txt"), []byte("complete"), 0o640); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := downloadSFTPTree(context.Background(), localReadFS(), source, destination); err != nil {
		t.Fatal(err)
	}
	downloadRoot := downloadArtifactPath(destination, filepath.ToSlash(source))
	got, err := os.ReadFile(filepath.Join(downloadRoot, "nested", "deep", "file.txt"))
	if err != nil || string(got) != "complete" {
		t.Fatalf("recursive SFTP content = %q, err=%v", got, err)
	}
	downloaded := filepath.Join(downloadRoot, "nested", "deep", "file.txt")
	info, err := os.Stat(downloaded)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("downloaded SFTP file mode=%v, want 0600", info.Mode().Perm())
	}
}

func mappedRootReadFS(source string) remoteReadFS {
	mapPath := func(remote string) string {
		if remote == "/" {
			return source
		}
		return filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(remote, "/")))
	}
	base := localReadFS()
	return remoteReadFS{
		lstat:   func(path string) (os.FileInfo, error) { return base.lstat(mapPath(path)) },
		readDir: func(path string) ([]os.FileInfo, error) { return base.readDir(mapPath(path)) },
		open:    func(path string) (io.ReadCloser, error) { return base.open(mapPath(path)) },
	}
}

func TestDownloadSFTPTreeRemoteRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote test paths use POSIX joining")
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "root-file"), []byte("root data"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := downloadSFTPTree(context.Background(), mappedRootReadFS(source), "/", destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "root-file"))
	if err != nil || string(got) != "root data" {
		t.Fatalf("root SFTP content=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(destination, filepath.Base(source), "root-file")); !os.IsNotExist(err) {
		t.Fatal("remote / was incorrectly nested under a local basename")
	}
}

func TestDownloadSFTPTreeRejectsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup is platform dependent")
	}
	sourceParent := t.TempDir()
	source := filepath.Join(sourceParent, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(sourceParent, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	err := downloadSFTPTree(context.Background(), localReadFS(), source, destination)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("downloadSFTPTree() error = %v, want explicit link rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "source", "link")); !os.IsNotExist(err) {
		t.Fatal("SFTP fallback materialized a remote link")
	}
}

func TestPayloadOutfileSanitizesLabelsAndUniquelyIdentifiesPayloads(t *testing.T) {
	base := Instance{
		IP:       "2001:db8::10",
		Hostname: "../bad\\host:CON?\n",
		Outfile:  "%h%/%i%/%s%.txt",
	}
	commandOne := base
	commandOne.ID = 0
	commandTwo := base
	commandTwo.ID = 1
	one := payloadOutfile(commandOne, "command")
	two := payloadOutfile(commandTwo, "command")
	if one == two {
		t.Fatalf("command output paths collided: %q", one)
	}
	for _, got := range []string{one, two} {
		if strings.ContainsAny(got, "\\:<>|?*\r\n") {
			t.Errorf("payloadOutfile() = %q, contains unsafe component text", got)
		}
		if strings.Contains(got, "2001:db8") || strings.Contains(got, "bad\\host") {
			t.Errorf("payloadOutfile() retained raw remote text: %q", got)
		}
	}

	scriptOne := base
	scriptOne.ID = 2
	scriptTwo := base
	scriptTwo.ID = 3
	first := payloadOutfile(scriptOne, scriptOutputBase("first/check.sh"))
	second := payloadOutfile(scriptTwo, scriptOutputBase("second/check.sh"))
	if first == second || !strings.Contains(first, "check-0003") || !strings.Contains(second, "check-0004") {
		t.Fatalf("same-basename script paths not uniquely labelled: %q %q", first, second)
	}
}

func TestPayloadOutfileAddsMissingCollisionDimensions(t *testing.T) {
	i := Instance{IP: "192.0.2.4", Hostname: "web04", ID: 6, Outfile: "fixed.txt"}
	got := filepath.ToSlash(payloadOutfile(i, "command"))
	if got != "fixed-web04-command-0007.txt" {
		t.Fatalf("payloadOutfile() = %q", got)
	}
}

func TestPersistPayloadOutputCreatesEmptyFileAndReportsExistingFile(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	logger.InitLoggerWithWriters(&bytes.Buffer{}, &bytes.Buffer{})
	i := Instance{IP: "192.0.2.1", Username: "root", ID: 40, Outfile: "host/empty.txt"}
	if err := persistPayloadOutput(i, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join("output", "host", "empty.txt"))
	if err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("empty output info=%v err=%v", info, err)
	}
	if err := persistPayloadOutput(i, "replacement"); err == nil {
		t.Fatal("existing output failure was not propagated")
	}
}

func TestParseDownloadEntryContainsDestinationsAndRejectsSymlinks(t *testing.T) {
	base := t.TempDir()
	for _, entry := range []string{"/var/log;../escape", `/var/log;..\\escape`, "/var/log;/absolute", `/var/log;C:\\absolute`} {
		if _, got, err := parseDownloadEntry(entry, base); err == nil {
			t.Errorf("parseDownloadEntry(%q) = %q, want error", entry, got)
		}
	}
	remote, got, err := parseDownloadEntry("/var/log;nested/logs", base)
	if err != nil || remote != "/var/log" || got != filepath.Join(base, "nested", "logs") {
		t.Fatalf("safe parse = remote %q destination %q err=%v", remote, got, err)
	}
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(base, "linked")); err == nil {
			if _, _, err := parseDownloadEntry("/var/log;linked/escape", base); err == nil {
				t.Fatal("parseDownloadEntry traversed a symlink")
			}
		}
	}
}

func TestReserveDownloadArtifactRejectsOverlapAndExisting(t *testing.T) {
	destination := t.TempDir()
	release, err := reserveDownloadArtifact(destination, "/a/log")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := reserveDownloadArtifact(destination, "/b/log"); err == nil {
		t.Fatal("same-basename downloads were allowed to overlap")
	}
	release()
	if err := os.WriteFile(filepath.Join(destination, "log"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveDownloadArtifact(destination, "/b/log"); err == nil {
		t.Fatal("existing download artifact was accepted")
	}
}

func TestReserveDownloadArtifactRejectsRootMergeAndOverlap(t *testing.T) {
	destination := t.TempDir()
	release, err := reserveDownloadArtifact(destination, "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveDownloadArtifact(destination, "/etc"); err == nil {
		t.Fatal("child download overlapped reserved remote root")
	}
	release()
	if err := os.WriteFile(filepath.Join(destination, "existing"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveDownloadArtifact(destination, "/"); err == nil {
		t.Fatal("remote root was allowed to merge into nonempty destination")
	}
}

func TestDownloadSFTPTreeUsesPortableRemoteNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local fixture needs a Unix-valid Windows-invalid name")
	}
	parent := t.TempDir()
	source := filepath.Join(parent, "bad:name")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "CON"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := downloadSFTPTree(context.Background(), localReadFS(), source, destination); err != nil {
		t.Fatal(err)
	}
	root := downloadArtifactPath(destination, filepath.ToSlash(source))
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("portable SFTP entries=%v err=%v", entries, err)
	}
	if strings.ContainsAny(filepath.Base(root)+entries[0].Name(), `:<>"|?*`) || entries[0].Name() == "CON" {
		t.Fatalf("SFTP materialized nonportable names: %q/%q", filepath.Base(root), entries[0].Name())
	}
}
