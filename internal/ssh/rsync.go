package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/melbahja/goph"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

// rsync.go layers rsync on top of the existing SSH connection for file
// transfer. rsync gives delta transfers, resume, and permission/timestamp
// preservation — a real win when the same toolkit is pushed repeatedly or logs
// are pulled again during an engagement.
//
// The tool authenticates in-process (goph), but rsync must shell out to the
// system `rsync`, which drives its own `ssh`. We bridge the two:
//   - key / agent auth passes straight through to ssh (-i / SSH_AUTH_SOCK),
//   - password auth uses a throwaway SSH_ASKPASS helper so nothing extra needs
//     to be installed locally and the password never lands on a command line.
//
// Every path degrades gracefully: if local rsync/ssh is missing, the remote has
// no rsync and we cannot install it, or a transfer errors, we fall back to the
// built-in tar/scp streaming.

// installTimeout bounds a remote package install; long enough for a slow mirror,
// short enough not to wedge the run if the box has no working network.
const installTimeout = 90 * time.Second

// transferIdleTimeout is rsync's --timeout: abort a transfer only if it stalls
// with no data for this long. Big transfers are fine as long as bytes flow.
const transferIdleTimeout = 60

// rsyncUsable decides, once per host, whether rsync can be used for this host's
// transfers. It confirms the local tooling, that we have a workable auth method,
// and that the remote has rsync (installing it when asked and permitted).
func rsyncUsable(i Instance, client *goph.Client) bool {
	if *NoRsync {
		return false
	}
	if !localRsyncAvailable() {
		logger.Debug("safe compatible local rsync/ssh unavailable; using built-in transfer")
		return false
	}
	if i.Password != "" && runtime.GOOS == "windows" {
		logger.Debug("password-mode rsync askpass is unavailable on native Windows; using built-in transfer")
		return false
	}
	// We need either a password or a key/agent to hand to ssh.
	if i.Password == "" && !keyTransportAvailable() {
		logger.Debug("no rsync-compatible auth for host; using built-in transfer")
		return false
	}
	if err := ensureRemoteRsync(i, client); err != nil {
		logger.InfoExtra(i, fmt.Sprintf("rsync unavailable on remote; using built-in transfer: %s", err))
		return false
	}
	return true
}

// localRsyncAvailable reports whether both rsync and ssh exist on this machine.
func localRsyncAvailable() bool {
	localRsyncOnce.Do(func() {
		if _, err := exec.LookPath("rsync"); err != nil {
			return
		}
		if _, err := exec.LookPath("ssh"); err != nil {
			return
		}
		// Old/OpenBSD rsync variants do not support protected arguments. Using
		// them would re-introduce remote-shell evaluation for spaces, globs, and
		// metacharacters, so prefer the built-in safe transfer in that case.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "rsync", "--protect-args", "--version")
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			logger.Debug("local rsync lacks --protect-args; using built-in transfer")
			return
		}
		localRsyncOK = true
	})
	return localRsyncOK
}

// keyTransportAvailable reports whether key- or agent-based auth is usable for
// ssh: an explicit private key path, or an ssh-agent socket in the environment.
func keyTransportAvailable() bool {
	keyPath := strings.TrimSpace(*Key)
	if keyPath != "" && keyPath != AgentKeyFlagValue {
		return true
	}
	return os.Getenv("SSH_AUTH_SOCK") != ""
}

// ensureRemoteRsync ensures the remote has rsync, attempting one bounded install
// when it is missing and we can act as root (directly or via sudo).
func ensureRemoteRsync(i Instance, client *goph.Client) error {
	hasRsync, err := remoteHasRsync(client)
	if err != nil {
		return fmt.Errorf("failed to probe for rsync: %w", err)
	}
	if hasRsync {
		return nil
	}
	logger.InfoExtra(i, "rsync missing on remote, attempting install")
	if err := installRemoteRsyncOnce(i, client); err != nil {
		return err
	}
	hasRsync, err = remoteHasRsync(client)
	if err != nil {
		return fmt.Errorf("failed to verify rsync installation: %w", err)
	}
	if !hasRsync {
		return errors.New("package manager completed but rsync is still unavailable")
	}
	return nil
}

// remoteHasRsync probes for rsync on the remote host.
func remoteHasRsync(client *goph.Client) (bool, error) {
	out, err := boundedCommand(client, probeCommandTimeout, shWrap("command -v rsync >/dev/null 2>&1 && echo yes || echo no"))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "yes" {
			return true, nil
		}
	}
	return false, nil
}

type rsyncInstallAttempt struct {
	done chan struct{}
	err  error
}

var rsyncInstallState = struct {
	sync.Mutex
	attempts map[string]*rsyncInstallAttempt
}{attempts: make(map[string]*rsyncInstallAttempt)}

var errUnsafeRemoteTree = errors.New("unsafe remote download tree")

var (
	localRsyncOnce sync.Once
	localRsyncOK   bool
)

// installRemoteRsyncOnce serializes and memoizes package installation for a
// host. Duplicate target entries or overlapping transfer phases therefore do
// not fight over the package-manager lock or repeat a failed mutation.
func installRemoteRsyncOnce(i Instance, client *goph.Client) error {
	key := fmt.Sprintf("%s@%s:%d", i.Username, i.IP, *Port)
	return installRsyncOnce(key, func() error { return installRemoteRsync(i, client) })
}

func installRsyncOnce(key string, install func() error) error {
	rsyncInstallState.Lock()
	if attempt, ok := rsyncInstallState.attempts[key]; ok {
		rsyncInstallState.Unlock()
		<-attempt.done
		return attempt.err
	}
	attempt := &rsyncInstallAttempt{done: make(chan struct{})}
	rsyncInstallState.attempts[key] = attempt
	rsyncInstallState.Unlock()

	attempt.err = install()
	close(attempt.done)
	return attempt.err
}

// installRemoteRsync tries to install rsync using the remote's package manager.
// It only runs when we are root or can sudo (per the user's chosen policy).
func installRemoteRsync(i Instance, client *goph.Client) error {
	mgr := detectPackageManager(client)
	if mgr == "" {
		return errors.New("no known package manager on remote")
	}
	installCmd := packageInstallCommand(mgr)
	if installCmd == "" {
		return fmt.Errorf("unsupported package manager %q", mgr)
	}
	logger.InfoExtra(i, fmt.Sprintf("installing rsync via %s", mgr))

	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()

	if i.Username == "root" {
		out, err := runCommand(client, ctx, shWrap(installCmd))
		if err != nil {
			return fmt.Errorf("%s install failed: %w: %s", mgr, err, firstLine(out))
		}
		return nil
	}
	if *Sudo && i.Password != "" {
		marker := newSudoInputBoundary(i.Password)
		out, err := runWithInput(client, ctx, sudoBoundaryCommand(installCmd, marker), sudoBoundaryInput(i.Password, marker, ""))
		if err != nil {
			return fmt.Errorf("sudo %s install failed: %w: %s", mgr, err, firstLine(out))
		}
		return nil
	}
	if *Sudo {
		out, err := runCommand(client, ctx, "sudo -n "+shWrap(installCmd))
		if err != nil {
			return fmt.Errorf("passwordless sudo %s install failed: %w: %s", mgr, err, firstLine(out))
		}
		return nil
	}
	return errors.New("rsync installation requires a root login or --sudo")
}

// detectPackageManager returns the first recognized package manager found on the
// remote host, or "" if none is present.
func detectPackageManager(client *goph.Client) string {
	probe := `for m in apt-get dnf yum zypper pacman apk pkg pkg_add; do ` +
		`if command -v "$m" >/dev/null 2>&1; then echo "$m"; break; fi; done`
	out, err := boundedCommand(client, probeCommandTimeout, shWrap(probe))
	if err != nil {
		return ""
	}
	return parsePackageManager(out)
}

func parsePackageManager(out []byte) string {
	known := map[string]bool{
		"apt-get": true, "dnf": true, "yum": true, "zypper": true,
		"pacman": true, "apk": true, "pkg": true, "pkg_add": true,
	}
	for _, line := range strings.Split(string(out), "\n") {
		manager := strings.TrimSpace(line)
		if known[manager] {
			return manager
		}
	}
	return ""
}

// packageInstallCommand maps a package manager to a non-interactive rsync
// install command. Covers Debian/Ubuntu, RHEL/Fedora, SUSE, Arch, Alpine, and
// the BSDs.
func packageInstallCommand(mgr string) string {
	switch mgr {
	case "apt-get":
		return "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends rsync"
	case "dnf":
		return "dnf -y --setopt=timeout=30 install rsync"
	case "yum":
		return "yum -y --setopt=timeout=30 install rsync"
	case "zypper":
		return "zypper --non-interactive install --no-recommends rsync"
	case "pacman":
		// Never refresh package databases without a full upgrade: `pacman -Sy`
		// followed by a single-package install creates an unsupported partial
		// upgrade. Use the already-synchronized database and fall back cleanly if
		// it is stale.
		return "pacman -S --needed --noconfirm rsync"
	case "apk":
		return "apk add --no-cache rsync"
	case "pkg": // FreeBSD
		return "env ASSUME_ALWAYS_YES=yes pkg install -y rsync"
	case "pkg_add": // OpenBSD
		return "pkg_add rsync"
	default:
		return ""
	}
}

// rsyncUpload copies a local file/dir to the remote path, matching the built-in
// transfer's placement semantics (a source directory lands as <remote>/<base>).
func rsyncUpload(ctx context.Context, i Instance, client *goph.Client, localPath, remotePath string) error {
	// Pre-create the destination directory so rsync can write into it, the same
	// way the tar-based path does with `mkdir -p`.
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local path '%s' not found: %w", localPath, err)
	}
	mkdirTarget := remotePath
	if !info.IsDir() {
		mkdirTarget = pathpkg.Dir(remotePath)
	}
	if _, err := boundedCommand(client, probeCommandTimeout, shWrap("mkdir -p -- "+shQuote(mkdirTarget))); err != nil {
		return fmt.Errorf("failed to create remote dir '%s': %w", mkdirTarget, err)
	}

	src, err := localRsyncOperand(localPath)
	if err != nil {
		return err
	}
	dst := remoteRsyncOperand(i, remotePath)
	return runRsyncContext(ctx, i, src, dst)
}

// rsyncDownload pulls a remote path into extractDir, creating extractDir/<base>
// to match the tar-based download layout.
func rsyncDownload(ctx context.Context, i Instance, client *goph.Client, extractDir, remotePath string) error {
	cleanRemote, err := normalizeRemoteDownloadPath(remotePath)
	if err != nil {
		return err
	}
	if err := validateRemoteDownloadTree(client, cleanRemote); err != nil {
		return err
	}
	src := remoteRsyncOperand(i, cleanRemote)
	destination := downloadArtifactPath(extractDir, cleanRemote)
	if cleanRemote == "/" {
		destination = extractDir
	}
	dst, err := localRsyncOperand(destination)
	if err != nil {
		return err
	}
	if cleanRemote == "/" {
		dst += string(os.PathSeparator)
	}
	err = runRsyncWithOptionsContext(ctx, i, src, dst,
		"--no-links", "--no-devices", "--no-specials",
		"--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=",
	)
	return errors.Join(err, hardenDownloadedArtifact(downloadArtifactPath(extractDir, cleanRemote)))
}

// validateRemoteDownloadTree applies the same no-link/no-special-file policy as
// the tar and SFTP paths before rsync starts. Rsync also receives skip options
// as defense in depth if the tree changes after this probe.
func validateRemoteDownloadTree(client *goph.Client, remotePath string) error {
	out, err := boundedCommand(client, probeCommandTimeout, remoteDownloadValidationCommand(remotePath))
	if err != nil {
		return fmt.Errorf("failed to validate remote download tree %q: %w", remotePath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "UNSAFE" {
			return fmt.Errorf("%w %q: contains a link or special file", errUnsafeRemoteTree, remotePath)
		}
	}
	return nil
}

func remoteDownloadValidationCommand(remotePath string) string {
	cmd := "p=" + shQuote(remotePath) + "; " +
		"if [ -L \"$p\" ] || { [ ! -f \"$p\" ] && [ ! -d \"$p\" ]; }; then printf '%s\\n' UNSAFE; " +
		"else find \"$p\" \\( -type l -o \\( ! -type f ! -type d \\) \\) -exec sh -c 'printf \"%s\\n\" UNSAFE' \\; -quit; fi"
	return shWrap(cmd)
}

func remoteRsyncOperand(i Instance, remotePath string) string {
	return fmt.Sprintf("%s@%s:%s", i.Username, rsyncHost(i.IP), remotePath)
}

// localRsyncOperand prevents leading dashes and colon-containing relative paths
// from being interpreted as options or remote operands by rsync.
func localRsyncOperand(localPath string) (string, error) {
	abs, err := filepath.Abs(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve local rsync path %q: %w", localPath, err)
	}
	return filepath.Clean(abs), nil
}

// runRsync executes rsync for a single source→destination, wiring up the SSH
// transport (host-key checks disabled, port, key/askpass) and reporting any
// combined output on failure.
func runRsync(i Instance, src, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), transferTimeout())
	defer cancel()
	return runRsyncContext(ctx, i, src, dst)
}

func runRsyncContext(ctx context.Context, i Instance, src, dst string) error {
	return runRsyncWithOptionsContext(ctx, i, src, dst)
}

func runRsyncWithOptionsContext(ctx context.Context, i Instance, src, dst string, extraOptions ...string) (retErr error) {
	rsh, env, cleanup, err := buildRsyncTransport(i)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer func() { retErr = errors.Join(retErr, cleanup()) }()
	}

	args := rsyncArgs(rsh, src, dst, extraOptions...)

	// Keep rsync's idle timeout and also impose the operator's end-to-end cap.
	// Unix builds kill rsync's process group (including ssh); other platforms use
	// CommandContext's direct kill. WaitDelay also bounds inherited output pipes.
	cmd := exec.CommandContext(ctx, "rsync", args...) // #nosec G204 -- executable is fixed and operands are separate, protected arguments.
	configureRsyncCancellation(cmd)
	cmd.Env = env
	cmd.WaitDelay = 2 * time.Second
	capture := &boundedCapture{}
	cmd.Stdout = capture
	cmd.Stderr = capture

	err = cmd.Run()
	out := capture.Bytes()
	captureErr := capture.Err()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("rsync timed out; process and pipes were terminated and partial transfer content may remain: %w", errors.Join(ctx.Err(), captureErr))
		}
		code := rsyncExitCode(err)
		if code == 23 || code == 24 {
			return fmt.Errorf("rsync partial transfer (exit %d; partial content retained for fallback/resume): %w: %s", code, errors.Join(err, captureErr), firstLine(out))
		}
		return fmt.Errorf("rsync failed: %w: %s", errors.Join(err, captureErr), firstLine(out))
	}
	if captureErr != nil {
		return fmt.Errorf("rsync output exceeded the capture limit: %w", captureErr)
	}
	logger.DebugExtra(i, "rsync transfer complete")
	return nil
}

func rsyncArgs(rsh, src, dst string, extraOptions ...string) []string {
	args := []string{
		"-a",        // archive: recurse, preserve perms/times/links
		"--partial", // keep partially transferred files for resume
		"--protect-args",
		fmt.Sprintf("--timeout=%d", transferIdleTimeout),
		"-e", rsh,
	}
	args = append(args, extraOptions...)
	return append(args, "--", src, dst)
}

// rsyncExitCode extracts the process exit code from an exec error, or -1 if the
// error is not a normal process exit.
func rsyncExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// firstLine returns the first non-empty line of rsync output, for a compact log.
func firstLine(b []byte) string {
	const maxDiagnosticInputBytes = 128
	for _, line := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			truncated := len(s) > maxDiagnosticInputBytes
			if truncated {
				s = s[:maxDiagnosticInputBytes]
			}
			// Escape control bytes before placing untrusted child output into logs.
			quoted := strconv.QuoteToGraphic(strings.ToValidUTF8(s, "�"))
			diagnostic := strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`)
			if truncated {
				diagnostic += "…"
			}
			return diagnostic
		}
	}
	return ""
}

// buildRsyncTransport assembles the `-e ssh ...` value and process environment
// rsync needs, plus a cleanup for any temporary askpass helper. Key/agent auth
// passes through natively; password auth is delivered via SSH_ASKPASS.
func buildRsyncTransport(i Instance) (rsh string, env []string, cleanup func() error, err error) {
	opts := []string{
		"ssh",
		"-p", fmt.Sprint(*Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "GlobalKnownHostsFile=" + os.DevNull,
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=10",
		"-o", "NumberOfPasswordPrompts=1",
	}
	env = os.Environ()

	if i.Password != "" {
		if runtime.GOOS == "windows" {
			return "", nil, nil, errors.New("password-mode rsync askpass is unsupported on native Windows; use built-in transfer")
		}
		// Password mode: force password auth (don't let agent keys get tried and
		// trip "too many authentication failures"), and feed the password via a
		// temporary askpass helper.
		opts = append(opts,
			"-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
		)
		askpassPath, cl, aerr := writeAskpassHelper()
		if aerr != nil {
			return "", nil, nil, aerr
		}
		cleanup = cl
		env = append(env,
			"COORD_ASKPASS_PW="+i.Password,
			"SSH_ASKPASS="+askpassPath,
			"SSH_ASKPASS_REQUIRE=force", // OpenSSH >= 8.4 honors this even with a tty
			"DISPLAY=coordinate:0",      // nudge older ssh to use the askpass helper
		)
	} else {
		// Key / agent mode.
		opts = append(opts, "-o", "PreferredAuthentications=publickey")
		keyPath := strings.TrimSpace(*Key)
		if keyPath != "" && keyPath != AgentKeyFlagValue {
			opts = append(opts, "-i", keyPath, "-o", "IdentitiesOnly=yes")
		}
	}

	quoted := make([]string, len(opts))
	for idx, opt := range opts {
		quoted[idx] = shQuote(opt)
	}
	return strings.Join(quoted, " "), env, cleanup, nil
}

// writeAskpassHelper writes a short-lived executable that prints the password
// from the environment. The password value lives only in the child process
// environment, never in the script body or a command line. Returns the path and
// a cleanup that removes it.
func writeAskpassHelper() (string, func() error, error) {
	f, err := os.CreateTemp("", "coordinate-askpass-*.sh")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create askpass helper: %w", err)
	}
	const script = "#!/bin/sh\nprintf '%s\\n' \"$COORD_ASKPASS_PW\"\n"
	if _, err := f.WriteString(script); err != nil {
		closeErr := f.Close()
		removeErr := os.Remove(f.Name())
		return "", nil, fmt.Errorf("failed to write askpass helper: %w", errors.Join(err, closeErr, removeErr))
	}
	if err := f.Close(); err != nil {
		return "", nil, fmt.Errorf("failed to close askpass helper: %w", errors.Join(err, os.Remove(f.Name())))
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		return "", nil, fmt.Errorf("failed to chmod askpass helper: %w", errors.Join(err, os.Remove(f.Name())))
	}
	path := f.Name()
	return path, func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove askpass helper: %w", err)
		}
		return nil
	}, nil
}

// rsyncHost formats a host for an rsync `user@host:path` target, bracketing IPv6
// literals as rsync/ssh require.
func rsyncHost(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}
