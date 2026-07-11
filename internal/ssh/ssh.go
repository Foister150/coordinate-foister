package ssh

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/melbahja/goph"

	. "github.com/LanodonF/coordinate-foister/internal/config"
	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/safepath"
	"github.com/LanodonF/coordinate-foister/internal/utils"
)

const (
	defaultCommandTimeout = 30 * time.Second
	probeCommandTimeout   = 10 * time.Second
)

// shQuote wraps a string in single quotes for safe inclusion in a POSIX shell
// command line, escaping any embedded single quotes. This is what lets us pass
// arbitrary user commands and script paths to the remote without a quoting flaw
// or shell injection.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shWrap forces cmd to run under POSIX /bin/sh regardless of the remote login
// shell. Root's login shell on the BSDs is frequently csh/tcsh, where bourne
// constructs like `VAR=val cmd`, pipes into redirections, and `command -v`
// simply do not parse. Routing everything through `sh -c` makes execution
// portable across Debian, Arch, Alpine, macOS, and the BSDs alike.
func shWrap(cmd string) string {
	return "sh -c " + shQuote(cmd)
}

// envPrefix exports the validated -E / env.json assignments before a payload.
// Each entire KEY=VALUE operand is single-quoted, so the remote shell cannot
// interpret spaces, quotes, dollars, backticks, semicolons, or newlines in a
// value. export also makes the values apply to every command in a compound
// direct-command payload, not only its first command.
func envPrefix() string {
	if len(EnvironCmds) == 0 {
		return ""
	}
	var b strings.Builder
	for _, assignment := range EnvironCmds {
		b.WriteString("export ")
		b.WriteString(shQuote(assignment))
		b.WriteString(" || exit 125; ")
	}
	return b.String()
}

// runWithInput runs a command on the remote host while feeding it data on stdin,
// honoring a context deadline. It is how we hand a sudo password to `sudo -S`
// over the SSH channel instead of embedding it in the command line — that keeps
// the password out of the remote process list and shell history, and sidesteps
// every quoting hazard around passwords that contain quotes, $ or backticks.
func runWithInput(client *goph.Client, ctx context.Context, cmd, input string) ([]byte, error) {
	session, err := newSessionContext(ctx, client)
	if err != nil {
		return nil, err
	}

	// crypto/ssh copies stdout and stderr concurrently. The bounded writer is
	// race-safe and prevents a chatty or hostile host from exhausting operator
	// memory. Exceeding the cap is returned as an explicit payload failure; the
	// retained prefix includes a truncation marker.
	buf := &boundedCapture{}
	session.Stdout = buf
	session.Stderr = buf
	if input != "" {
		session.Stdin = strings.NewReader(input)
	}

	if err := session.Start(cmd); err != nil {
		_ = session.Close()
		return buf.Bytes(), err
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case <-ctx.Done():
		// Close normally tears down the channel immediately, causing Wait and all
		// I/O copy loops to return. Do it asynchronously because crypto/ssh channel
		// writes can themselves block behind a stalled transport or key exchange.
		go func() {
			_ = client.Close()
			_ = session.Close()
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return buf.Bytes(), errors.Join(ctx.Err(), buf.Err())
	case err := <-done:
		_ = session.Close()
		return buf.Bytes(), errors.Join(err, buf.Err())
	}
}

// runCommand is the single context-aware session path for remote commands.
// goph v1.4.0's RunContext can return without closing its session, leaving a
// goroutine blocked in Wait. runWithInput always closes on cancellation.
func runCommand(client *goph.Client, ctx context.Context, cmd string) ([]byte, error) {
	return runWithInput(client, ctx, cmd, "")
}

func boundedCommand(client *goph.Client, timeout time.Duration, cmd string) ([]byte, error) {
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runCommand(client, ctx, cmd)
}

func payloadTimeout() time.Duration {
	if Timeout > 0 {
		return Timeout
	}
	return defaultCommandTimeout
}

// resolveHostname fills i.Hostname when it has not already been resolved. It is
// safe to call more than once; the guard prevents the redundant round trips the
// old code made (once in the wrapper, again in every ssher/ssherCommand).
func resolveHostname(i *Instance, client *goph.Client) {
	if i.Hostname != "" {
		return
	}
	output, err := boundedCommand(client, probeCommandTimeout, "hostname")
	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		output, err = boundedCommand(client, probeCommandTimeout, "cat /etc/hostname")
	}
	stroutput := strings.TrimSpace(string(output))
	if err == nil && stroutput != "" && !strings.Contains(stroutput, "No such file or directory") {
		i.Hostname = stroutput
	} else {
		i.Hostname = i.IP
	}
	logger.Debug(fmt.Sprintf("Resolved hostname: %s", i.Hostname))
}

// shellUsable checks that we can actually drive a POSIX shell on the host and
// read its stdout back. Honors -n/--no-validate, which skips the probe.
func shellUsable(i Instance, client *goph.Client) bool {
	if *NoValidate {
		return true
	}
	output, _ := boundedCommand(client, probeCommandTimeout, shWrap("echo coordinate_ok"))
	if !strings.Contains(string(output), "coordinate_ok") {
		logger.Err(fmt.Sprintf("%s: Couldn't read stdout. Coordinate can't drive this host's shell.\n", i.IP))
		return false
	}
	return true
}

type scriptPreparation struct {
	ready   chan struct{}
	content string
	err     error
}

// preparedScripts caches immutable local script bytes for this process run.
// Host workers start concurrently, so the ready channel also makes the first
// read a single-flight operation instead of allowing every host to race-read
// and normalize the same file.
var preparedScripts sync.Map

var (
	downloadReservationMu sync.Mutex
	downloadReservations  = make(map[string]struct{})
)

func prepareScript(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	candidate := &scriptPreparation{ready: make(chan struct{})}
	actual, loaded := preparedScripts.LoadOrStore(absPath, candidate)
	prepared := actual.(*scriptPreparation)
	if !loaded {
		contents, readErr := os.ReadFile(absPath)
		prepared.content = normalizeScript(string(contents))
		prepared.err = readErr
		close(prepared.ready)
	} else {
		<-prepared.ready
	}
	return prepared.content, prepared.err
}

func SsherWrapper(i Instance, client *goph.Client) HostWorkResult {
	logger.Debug(fmt.Sprintf("Starting host work for %s as %s", i.IP, i.Username))
	result := HostWorkResult{PayloadsRequested: len(Scripts), TransfersRequested: boolInt(len(*UploadFiles) > 0) + boolInt(len(*DownloadDirs) > 0)}
	if len(Commands) > 0 {
		result.PayloadsRequested = len(Commands)
	}
	var wg sync.WaitGroup
	prepared := make(map[string]string, len(Scripts))
	for _, path := range Scripts {
		contents, err := prepareScript(path)
		if err != nil {
			logger.Crit(i, errors.New("Error reading "+path+": "+err.Error()))
			result.Failures = append(result.Failures, fmt.Errorf("read local script %q: %w", path, err))
			return result
		}
		prepared[path] = contents
	}

	// Resolve hostname early so downloads can use it for directory names
	resolveHostname(&i, client)
	if err := reservePayloadOutputs(i); err != nil {
		msg := fmt.Sprintf("refusing unsafe or colliding output for %s: %s", hostLabel(i), err)
		logger.ErrExtra(i, msg)
		result.Failures = append(result.Failures, errors.New(msg))
		return result
	}

	// Shell validation and sudo authentication are host capabilities, not
	// payload properties. Probe each once before starting concurrent work so a
	// bad sudo password cannot trigger several simultaneous PAM failures.
	hasPayloads := len(Commands) > 0 || len(Scripts) > 0
	useSudo := false
	if hasPayloads {
		if !shellUsable(i, client) {
			result.Failures = append(result.Failures, fmt.Errorf("shell validation failed on %s", hostLabel(i)))
			return result
		}
		sudo := shouldSudo(&i, client)
		if sudo == sudoFailed {
			msg := fmt.Sprintf("sudo escalation failed on %s; refusing to run payloads unprivileged", hostLabel(i))
			logger.ErrExtra(i, msg)
			result.Failures = append(result.Failures, errors.New(msg))
			return result
		}
		useSudo = sudo == sudoAvailable
	}

	// Probe/install rsync once for the entire host, even when both upload and
	// download phases are requested. This avoids duplicate package mutations.
	useRsync := false
	if len(*UploadFiles) > 0 || len(*DownloadDirs) > 0 {
		release, _ := expensiveOperations.acquire(context.Background())
		useRsync = rsyncUsable(i, client)
		release()
	}
	var transferErrs []error

	// Upload local files/dirs if -F flags were specified
	if len(*UploadFiles) > 0 {
		logger.Debug(fmt.Sprintf("Upload files requested: %v", *UploadFiles))
		err := uploadToRemote(i, client, useRsync)
		result.Transfers = append(result.Transfers, OperationResult{Kind: "upload", Label: "uploads", Err: err})
		if err != nil {
			transferErrs = append(transferErrs, err)
		}
	}

	// Download remote directories if -D flags were specified
	if len(*DownloadDirs) > 0 {
		logger.Debug(fmt.Sprintf("Download directories requested: %v", *DownloadDirs))
		err := downloadRemoteDirs(i, client, useRsync)
		result.Transfers = append(result.Transfers, OperationResult{Kind: "download", Label: "downloads", Err: err})
		if err != nil {
			transferErrs = append(transferErrs, err)
		}
	}
	transferErr := errors.Join(transferErrs...)
	if transferErr != nil {
		msg := fmt.Sprintf("transfer failure on %s: %s", hostLabel(i), transferErr)
		logger.ErrExtra(i, msg)
		// Uploads are commonly prerequisites for the requested payload. Never
		// continue into commands/scripts with missing or partial transfer state.
		return result
	}

	// If only uploading/downloading (no scripts or commands), we're done
	if len(Commands) == 0 && len(Scripts) == 0 {
		return result
	}

	// -l bounds how many scripts/commands run at once on this single host.
	sem := make(chan struct{}, max(1, *Threads))

	// Handle direct commands if specified
	if len(Commands) > 0 {
		outcomes := make(chan OperationResult, len(Commands))
		logger.Debug("Executing direct commands instead of scripts")
		for _, command := range Commands {
			logger.Debug("Preparing direct command (contents omitted)")
			inst := i
			// Keep command text out of Instance: it is used in log summaries and
			// output identity. A stable numeric label is sufficient context.
			inst.Script = fmt.Sprintf("command-%04d", inst.ID+1)
			inst.Outfile = payloadOutfile(inst, "command")
			fullCommand := envPrefix() + command

			wg.Add(1)
			sem <- struct{}{}
			go func(inst Instance, cmd string) {
				defer wg.Done()
				defer func() { <-sem }()
				outcomes <- OperationResult{Kind: "command", Label: inst.Script, Err: ssherCommand(inst, client, cmd, useSudo)}
			}(inst, fullCommand)
			i.ID++
		}
		wg.Wait()
		close(outcomes)
		for outcome := range outcomes {
			result.Payloads = append(result.Payloads, outcome)
		}
		logger.Debug("Finished executing all commands in SsherWrapper.")
		return result
	}

	// Handle scripts: each script runs exactly once per host. The old code ran
	// each one min(-l, len(scripts)) times, executing scripts multiple times by
	// accident; -l is now a real concurrency bound, not a repeat count.
	resultChannel := make(chan OperationResult, len(Scripts))
	for _, path := range Scripts {
		logger.Debug(fmt.Sprintf("Processing script path: %s", path))
		inst := i
		inst.Script = path
		inst.Outfile = payloadOutfile(inst, scriptOutputBase(path))

		wg.Add(1)
		sem <- struct{}{}
		go func(inst Instance, script string) {
			defer wg.Done()
			defer func() { <-sem }()
			resultChannel <- OperationResult{Kind: "script", Label: safepath.SanitizeComponent(scriptOutputBase(inst.Script)), Err: ssher(inst, client, script, useSudo)}
		}(inst, prepared[path])
		i.ID++
	}

	wg.Wait()
	close(resultChannel)
	for outcome := range resultChannel {
		result.Payloads = append(result.Payloads, outcome)
	}
	logger.Debug("Finished executing all scripts in SsherWrapper.")
	return result
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func scriptOutputBase(scriptPath string) string {
	base := filepath.Base(scriptPath)
	if strings.EqualFold(filepath.Ext(base), ".sh") {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return base
}

// payloadOutfile resolves only sanitized remote/local labels into the template.
// If a template omits the host or payload placeholder, the corresponding label
// is appended automatically so parallel hosts and payloads cannot share a file.
func payloadOutfile(i Instance, payloadBase string) string {
	if i.Outfile == "" {
		return ""
	}
	template := strings.ReplaceAll(i.Outfile, `\`, "/")
	hasHost := strings.Contains(template, "%i%") || strings.Contains(template, "%h%")
	hasPayload := strings.Contains(template, "%s%")
	ipLabel := safepath.SanitizeComponent(i.IP)
	hostLabel := safepath.SanitizeComponent(i.Hostname)
	payloadLabel := fmt.Sprintf("%s-%04d", safepath.SanitizeComponent(payloadBase), i.ID+1)
	resolved := strings.ReplaceAll(template, "%i%", ipLabel)
	resolved = strings.ReplaceAll(resolved, "%h%", hostLabel)
	resolved = strings.ReplaceAll(resolved, "%s%", payloadLabel)
	var suffixes []string
	if !hasHost {
		suffixes = append(suffixes, hostLabel)
	}
	if !hasPayload {
		suffixes = append(suffixes, payloadLabel)
	}
	if len(suffixes) > 0 {
		resolved = appendOutputSuffix(resolved, strings.Join(suffixes, "-"))
	}
	return filepath.FromSlash(resolved)
}

func appendOutputSuffix(name, suffix string) string {
	dir, leaf := pathpkg.Split(name)
	ext := pathpkg.Ext(leaf)
	stem := strings.TrimSuffix(leaf, ext)
	return dir + stem + "-" + suffix + ext
}

func reservePayloadOutputs(i Instance) error {
	if i.Outfile == "" {
		return nil
	}
	if len(Commands) > 0 {
		for index := range Commands {
			inst := i
			inst.ID += index
			inst.Script = "command"
			inst.Outfile = payloadOutfile(inst, "command")
			if err := logger.ReserveOutput(inst); err != nil {
				return err
			}
		}
		return nil
	}
	for index, scriptPath := range Scripts {
		inst := i
		inst.ID += index
		inst.Script = scriptPath
		inst.Outfile = payloadOutfile(inst, scriptOutputBase(scriptPath))
		if err := logger.ReserveOutput(inst); err != nil {
			return err
		}
	}
	return nil
}

func ssherCommand(i Instance, client *goph.Client, command string, useSudo bool) error {
	logger.Debug(fmt.Sprintf("Starting command %d on %s as %s (contents omitted)", i.ID, i.IP, i.Username))
	release := acquirePayloadSlot()
	defer release()

	logger.Debug(fmt.Sprintf("Resolved output file path: %s", i.Outfile))

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), payloadTimeout())
	defer cancel()

	var output []byte
	var err error
	if !useSudo {
		// Wrap in `sh -c` so the command runs under POSIX sh no matter what the
		// remote login shell is (csh/tcsh on the BSDs would choke otherwise).
		output, err = runCommand(client, ctx, shWrap(command))
	} else {
		// A cached ticket or NOPASSWD rule may leave the password unread. Frame
		// stdin so the privileged shell discards it before an arbitrary payload
		// can inherit stdin.
		marker := newSudoInputBoundary(i.Password)
		output, err = runWithInput(client, ctx, sudoBoundaryCommand(command, marker), sudoBoundaryInput(i.Password, marker, ""))
	}
	stroutput := string(output)

	if err != nil {
		if isTimeout(err) {
			logger.ErrExtra(i, fmt.Sprintf("command timed out on %s", hostLabel(i)))
		} else if errors.Is(err, errRemoteOutputLimit) {
			logger.ErrExtra(i, fmt.Sprintf("command output exceeded the %d-byte capture limit on %s; retained output is truncated", maxCapturedRemoteOutput, hostLabel(i)))
		} else {
			logger.ErrExtra(i, fmt.Sprintf("command failed: %s", err))
		}
	}

	outputErr := persistPayloadOutput(i, stroutput)
	if outputErr != nil {
		logger.ErrExtra(i, fmt.Sprintf("failed to save command output: %s", outputErr))
	}
	if len(stroutput) > 0 {
		harvestRootCreds(i, stroutput)
	}
	return errors.Join(err, outputErr)
}

func ssher(i Instance, client *goph.Client, script string, useSudo bool) (retErr error) {
	logger.Debug(fmt.Sprintf("Starting script %d on %s as %s (length %d)", i.ID, i.IP, i.Username, len(script)))
	release := acquirePayloadSlot()
	defer release()

	logger.Debug(fmt.Sprintf("Resolved output file path: %s", i.Outfile))
	if useSudo {
		// Never ask root to open the user-owned SCP pathname. Stream the exact
		// local bytes into a directory/file created by root in the same privileged
		// shell, then execute that root-owned immutable copy.
		rootDir := "/tmp/coordinate-root." + utils.GenerateRandomFileName(20)
		marker := newSudoInputBoundary(i.Password, script)
		ctx, cancel := context.WithTimeout(context.Background(), payloadTimeout())
		defer cancel()
		output, err := runWithInput(client, ctx, privilegedScriptCommand(rootDir, marker), sudoBoundaryInput(i.Password, marker, script))
		// Verify cleanup even after a successful payload: a failing EXIT trap must
		// not be silently counted as success, and an attacker-recreated pathname
		// must be reported without being removed.
		if cleanupErr := cleanupPrivilegedScriptDir(i, client, rootDir); cleanupErr != nil {
			logger.ErrExtra(i, fmt.Sprintf("failed to verify privileged script cleanup: %s", cleanupErr))
			retErr = errors.Join(retErr, fmt.Errorf("privileged script cleanup: %w", cleanupErr))
		}
		stroutput := string(output)
		if err != nil {
			if isTimeout(err) {
				logger.ErrExtra(i, fmt.Sprintf("script timed out on %s", hostLabel(i)))
			} else if errors.Is(err, errRemoteOutputLimit) {
				logger.ErrExtra(i, fmt.Sprintf("script output exceeded the %d-byte capture limit on %s; retained output is truncated", maxCapturedRemoteOutput, hostLabel(i)))
			} else {
				logger.ErrExtra(i, fmt.Sprintf("script failed: %s", err))
			}
		}
		outputErr := persistPayloadOutput(i, stroutput)
		if outputErr != nil {
			logger.ErrExtra(i, fmt.Sprintf("failed to save script output: %s", outputErr))
		}
		if stroutput != "" {
			harvestRootCreds(i, stroutput)
		}
		return errors.Join(retErr, err, outputErr)
	}

	filename := fmt.Sprintf("%s/%s", *TmpDir, utils.GenerateRandomFileName(16))
	logger.Debug(fmt.Sprintf("Generated temporary filename: %s", filename))
	err := os.WriteFile(filename, []byte(script), 0600)
	if err != nil {
		logger.Err(fmt.Sprintf("Error writing to temporary file: %s", filename))
		return fmt.Errorf("write local temporary script: %w", err)
	}
	defer func() {
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			logger.ErrExtra(i, fmt.Sprintf("failed to remove local temporary script: %s", err))
			retErr = errors.Join(retErr, fmt.Errorf("remove local temporary script: %w", err))
			return
		}
		logger.Debug(fmt.Sprintf("Removed local temporary script: %s", filename))
	}()
	logger.Debug(fmt.Sprintf("Script written to temporary file: %s", filename))

	remoteDir, err := createRemoteScriptDir(client)
	if err != nil {
		msg := fmt.Sprintf("failed to create a secure script directory on %s: %s", hostLabel(i), err)
		logger.ErrExtra(i, msg)
		return errors.New(msg)
	}
	defer func() {
		if err := cleanupRemoteScriptDir(client, remoteDir); err != nil {
			msg := fmt.Sprintf("failed to clean up remote script directory %s on %s: %s", remoteDir, hostLabel(i), err)
			logger.ErrExtra(i, msg)
			retErr = errors.Join(retErr, errors.New(msg))
		}
	}()
	remoteFilename := remoteDir + "/payload"

	if err := Upload(client, filename, remoteFilename); err != nil {
		return fmt.Errorf("upload script: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), payloadTimeout())
	defer cancel()

	// Run the uploaded script. Cleanup is deliberately performed in a separate
	// best-effort SSH session by the defer above, so it still runs when this
	// session times out or the payload exits nonzero. The environment values
	// are spliced in front of the script path (KEY=val /tmp/xxx) rather than
	// baked into the file — prepending them to the file body would push text in
	// front of the shebang and break interpreter selection.
	payload := envPrefix() + shQuote(remoteFilename)
	var output []byte
	output, err = runCommand(client, ctx, shWrap(payload))
	stroutput := string(output)

	if err != nil {
		if isTimeout(err) {
			logger.ErrExtra(i, fmt.Sprintf("script timed out on %s", hostLabel(i)))
		} else if errors.Is(err, errRemoteOutputLimit) {
			logger.ErrExtra(i, fmt.Sprintf("script output exceeded the %d-byte capture limit on %s; retained output is truncated", maxCapturedRemoteOutput, hostLabel(i)))
		} else {
			logger.ErrExtra(i, fmt.Sprintf("script failed: %s", err))
		}
	}
	outputErr := persistPayloadOutput(i, stroutput)
	if outputErr != nil {
		logger.ErrExtra(i, fmt.Sprintf("failed to save script output: %s", outputErr))
	}
	if len(stroutput) > 0 {
		harvestRootCreds(i, stroutput)
	}
	return errors.Join(err, outputErr)
}

func persistPayloadOutput(i Instance, output string) error {
	if output != "" {
		return logger.Stdout(i, output)
	}
	return logger.SaveOutput(i, nil)
}

// shouldSudo returns a three-state decision so an explicit failed escalation
// can never be mistaken for permission to run the payload unprivileged.
func shouldSudo(i *Instance, client *goph.Client) sudoDecision {
	preflight := decideSudo(i.Username, *Sudo, false)
	if preflight == sudoNotNeeded {
		if i.Username == "root" {
			return sudoNotNeeded
		}
		logger.InfoExtra(*i, "Not root, not sudoing. Proceeding with user.")
		return sudoNotNeeded
	}
	logger.Debug("Sudo is enabled. Attempting privilege escalation.")
	decision := decideSudo(i.Username, true, escalateSudo(*i, client))
	if decision == sudoAvailable {
		logger.InfoExtra(*i, "Privilege escalation succeeded.")
		return decision
	}
	logger.InfoExtra(*i, "Privilege escalation failed.")
	return decision
}

const remoteScriptDirTemplate = "/tmp/coordinate.XXXXXXXXXX"

// createRemoteScriptDir allocates a directory that only the authenticated user
// can modify for ordinary, unprivileged execution.
func createRemoteScriptDir(client *goph.Client) (string, error) {
	cmd := "umask 077; d=$(mktemp -d " + shQuote(remoteScriptDirTemplate) + ") || exit 1; " +
		"chmod 700 \"$d\" || { rm -rf \"$d\"; exit 1; }; printf '%s\\n' \"$d\""
	out, err := boundedCommand(client, probeCommandTimeout, shWrap(cmd))
	if err != nil {
		return "", err
	}
	return parseRemoteScriptDir(out)
}

func normalizeScript(script string) string {
	// Preserve the historical dos2unix behavior, which removed CR bytes, while
	// doing it in memory before either the streamed-sudo or SCP path.
	return strings.ReplaceAll(script, "\r", "")
}

func parseRemoteScriptDir(out []byte) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return "", errors.New("mktemp returned no path")
	}
	dir := strings.TrimSpace(lines[len(lines)-1])
	const prefix = "/tmp/coordinate."
	suffix := strings.TrimPrefix(dir, prefix)
	if suffix == dir || suffix == "" || strings.ContainsAny(suffix, "/\\\r\n") {
		return "", fmt.Errorf("mktemp returned unexpected path %q", dir)
	}
	return dir, nil
}

// cleanupRemoteScriptDir uses its own bounded session so payload timeouts and
// failures cannot bypass cleanup.
func cleanupRemoteScriptDir(client *goph.Client, remoteDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := runCommand(client, ctx, shWrap("rm -rf -- "+shQuote(remoteDir)))
	return err
}

// rootOwnedScriptPayload creates and executes the payload entirely as root.
// mkdir deliberately lacks -p: a guessed/precreated pathname fails closed.
func rootOwnedScriptPayload(remoteDir string) string {
	execute := envPrefix() + "\"$p\""
	return "umask 077; d=" + shQuote(remoteDir) + "; mkdir -- \"$d\" || exit 126; " +
		"trap 'rm -rf -- \"$d\"' 0 HUP INT TERM; p=\"$d/payload\"; " +
		"cat > \"$p\" || exit 126; chmod 500 \"$p\" && chmod 500 \"$d\" || exit 126; " + execute
}

// privilegedScriptCommand uses a random boundary between the sudo password and
// script bytes. Password-requiring sudo consumes the first line; NOPASSWD sudo
// leaves it for the root shell, which discards everything through the boundary.
// Either way, only exact post-boundary script bytes reach the root-owned file.
func privilegedScriptCommand(remoteDir, marker string) string {
	return sudoBoundaryCommand(rootOwnedScriptPayload(remoteDir), marker)
}

func cleanupPrivilegedScriptDir(i Instance, client *goph.Client, remoteDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := privilegedCleanupPayload(remoteDir)
	marker := newSudoInputBoundary(i.Password)
	_, err := runWithInput(client, ctx, sudoBoundaryCommand(payload, marker), sudoBoundaryInput(i.Password, marker, ""))
	return err
}

func privilegedCleanupPayload(remoteDir string) string {
	// Absence means the root shell's trap succeeded. Any replacement must be a
	// real root-owned directory; symlinks, files, and user-owned directories fail
	// visibly and are never removed. A final check verifies rm actually worked.
	return "d=" + shQuote(remoteDir) + "; " +
		"if [ ! -e \"$d\" ] && [ ! -L \"$d\" ]; then exit 0; fi; " +
		"[ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 125; " +
		"owner=$(stat -c '%u' \"$d\" 2>/dev/null || stat -f '%u' \"$d\" 2>/dev/null) || exit 125; " +
		"[ \"$owner\" = 0 ] || exit 125; rm -rf -- \"$d\" || exit 125; " +
		"[ ! -e \"$d\" ] && [ ! -L \"$d\" ]"
}

// isTimeout reports whether err is our context deadline being hit.
func isTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded")
}

// hostLabel prefers the resolved hostname, falling back to the IP.
func hostLabel(i Instance) string {
	if len(i.Hostname) > 0 {
		return i.Hostname
	}
	return i.IP
}

// harvestRootCreds scans script/command stdout for `root,<password>` lines and
// records them to the config store when --create-config is active. Preserves
// the original password.sh integration behavior.
func harvestRootCreds(i Instance, stdout string) {
	if *CreateConfig == "" {
		return
	}
	for _, line := range strings.Split(stdout, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 || parts[0] != "root" {
			continue
		}
		UpdateEntry(ConfigEntry{IP: i.IP, Username: "root", Password: parts[1]})
	}
}

// UploadToRemote uploads local files/directories to remote hosts.
// Uses streaming tar over SSH stdin — no temp files, no SCP binary needed on remote.
// Format: -F "local_path;remote_path"
func UploadToRemote(i Instance, client *goph.Client) error {
	return uploadToRemote(i, client, rsyncUsable(i, client))
}

func uploadToRemote(i Instance, client *goph.Client, useRsync bool) error {
	if useRsync {
		logger.DebugExtra(i, "using rsync for uploads")
	}

	var wg sync.WaitGroup
	results := make(chan error, len(*UploadFiles))
	sem := make(chan struct{}, max(1, *Threads))
	for _, entry := range *UploadFiles {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(entry string) {
			defer wg.Done()
			defer func() { <-sem }()
			results <- uploadSingleEntry(i, client, entry, useRsync)
		}(entry)
	}
	wg.Wait()
	close(results)
	var errs []error
	for err := range results {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func uploadSingleEntry(i Instance, client *goph.Client, entry string, useRsync bool) error {
	return runTransferOperation("upload "+entry, func(ctx context.Context) error {
		return uploadSingleEntryContext(ctx, i, client, entry, useRsync)
	})
}

func uploadSingleEntryContext(ctx context.Context, i Instance, client *goph.Client, entry string, useRsync bool) error {
	// Parse local;remote syntax
	parts := strings.SplitN(entry, ";", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("invalid upload format %q; use local_path;remote_path", entry)
	}
	localPath := strings.TrimSpace(parts[0])
	remotePath := strings.TrimSpace(parts[1])

	// Check local path exists
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local upload path %q not found: %w", localPath, err)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("local upload path %q must be a regular file or directory", localPath)
	}

	// Prefer rsync; fall back to the built-in streaming transfer on any error so
	// a single flaky rsync never loses the upload.
	var rsyncErr error
	if useRsync {
		logger.InfoExtra(i, fmt.Sprintf("Uploading %s -> %s (rsync)", localPath, remotePath))
		if err := rsyncUpload(ctx, i, client, localPath, remotePath); err == nil {
			logger.InfoExtra(i, fmt.Sprintf("Successfully uploaded %s -> %s (rsync)", localPath, remotePath))
			return nil
		} else {
			rsyncErr = err
			logger.InfoExtra(i, fmt.Sprintf("rsync upload of '%s' failed; trying built-in transfer", localPath))
		}
	}

	logger.InfoExtra(i, fmt.Sprintf("Uploading %s -> %s (streaming)", localPath, remotePath))

	if info.IsDir() {
		err = streamUploadDir(ctx, client, localPath, remotePath)
	} else {
		err = streamUploadFile(ctx, client, localPath, remotePath)
	}

	if err != nil {
		return fmt.Errorf("failed to upload %q: %w", localPath, errors.Join(rsyncErr, err))
	}
	method := "streaming"
	if rsyncErr != nil {
		method = "streaming fallback"
	}
	logger.InfoExtra(i, fmt.Sprintf("Successfully uploaded %s -> %s (%s)", localPath, remotePath, method))
	return nil
}

// streamUploadDir tars a local directory and streams it over SSH stdin to extract on remote.
// One pipe, no temp files on either side.
func streamUploadDir(ctx context.Context, client *goph.Client, localDir string, remotePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := newSessionContext(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Remote: create destination and extract tar from stdin
	remoteCmd := streamUploadDirCommand(remotePath)
	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start remote extract: %w", err)
	}
	stopWatcher := closeOnContext(ctx, func() error {
		_ = client.Close()
		return session.Close()
	})
	defer stopWatcher()

	// Local: tar the directory and write to SSH stdin
	writeErr := writeUploadTar(localDir, stdin)
	stdinCloseErr := stdin.Close() // Signal EOF to remote tar

	sessionErr := session.Wait()

	if err := errors.Join(writeErr, stdinCloseErr); err != nil {
		return fmt.Errorf("local tar stream error: %w", err)
	}
	if sessionErr != nil {
		return fmt.Errorf("remote extract error: %w", sessionErr)
	}
	return nil
}

// writeUploadTar is intentionally strict: any walk, metadata, open, read,
// close, header, or tar-close failure makes the upload fail. The previous
// helper silently skipped unreadable/vanished files and could report an
// incomplete source tree as a successful upload.
func writeUploadTar(sourceDir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	sourceDir = filepath.Clean(sourceDir)
	baseDir := filepath.Base(sourceDir)
	walkErr := filepath.Walk(sourceDir, func(localPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relPath, err := filepath.Rel(sourceDir, localPath)
		if err != nil {
			return fmt.Errorf("failed to resolve upload path %q: %w", localPath, err)
		}
		tarPath := filepath.ToSlash(filepath.Join(baseDir, relPath))
		if relPath == "." {
			tarPath = baseDir
		}

		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(localPath)
			if err != nil {
				return fmt.Errorf("failed to read upload link %q: %w", localPath, err)
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("failed to build tar header for %q: %w", localPath, err)
		}
		header.Name = tarPath
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %q: %w", localPath, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(localPath)
		if err != nil {
			return fmt.Errorf("failed to open upload file %q: %w", localPath, err)
		}
		_, copyErr := io.Copy(tw, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return fmt.Errorf("failed to read upload file %q: %w", localPath, err)
		}
		return nil
	})
	closeErr := tw.Close()
	return errors.Join(walkErr, closeErr)
}

func streamUploadDirCommand(remotePath string) string {
	return shWrap("mkdir -p -- " + shQuote(remotePath) + " && tar xf - -C " + shQuote(remotePath))
}

// streamUploadFile streams a single file over SSH stdin using cat.
// Faster than SCP for single files — no protocol overhead.
func streamUploadFile(ctx context.Context, client *goph.Client, localFile string, remotePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := newSessionContext(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Get local file info for permissions
	info, err := os.Stat(localFile)
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}

	// Remote: preserve executable bit
	perm := "644"
	if info.Mode()&0111 != 0 {
		perm = "755"
	}

	// Let the remote shell figure out if dest is a directory.
	// If /root is a dir → writes to /root/meow. If /root/meow is a path → writes there.
	localName := filepath.Base(localFile)
	remoteCmd := streamUploadFileCommand(remotePath, localName, perm)
	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start remote write: %w", err)
	}
	stopWatcher := closeOnContext(ctx, func() error {
		_ = client.Close()
		return session.Close()
	})
	defer stopWatcher()

	// Stream local file to SSH stdin
	f, err := os.Open(localFile)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to open local file: %w", err), stdin.Close())
	}

	_, copyErr := io.Copy(stdin, f)
	fileCloseErr := f.Close()
	stdinCloseErr := stdin.Close()

	sessionErr := session.Wait()

	if err := errors.Join(copyErr, fileCloseErr, stdinCloseErr); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}
	if sessionErr != nil {
		return fmt.Errorf("remote write error: %w", sessionErr)
	}
	return nil
}

func streamUploadFileCommand(remotePath, localName, perm string) string {
	cmd := "d=" + shQuote(remotePath) + "; n=" + shQuote(localName) +
		"; if [ -d \"$d\" ]; then d=\"$d/$n\"; fi; " +
		"case \"$d\" in */*) parent=${d%/*}; [ -n \"$parent\" ] || parent=/;; *) parent=.;; esac; " +
		"mkdir -p -- \"$parent\" && cat > \"$d\" && chmod " + perm + " \"$d\""
	return shWrap(cmd)
}

// probeRemote checks what archiving tools exist on the remote. Called once per
// host so we never waste time on fallback methods we know will fail.
func probeRemote(client *goph.Client) (hasTar, hasGzip bool) {
	out, err := boundedCommand(client, probeCommandTimeout, shWrap("command -v tar >/dev/null 2>&1 && echo TAR; command -v gzip >/dev/null 2>&1 && echo GZIP"))
	if err != nil {
		// 'command' builtin may not exist (old sh); try 'which'
		out, _ = boundedCommand(client, probeCommandTimeout, shWrap("which tar >/dev/null 2>&1 && echo TAR; which gzip >/dev/null 2>&1 && echo GZIP"))
	}
	s := string(out)
	hasTar = strings.Contains(s, "TAR")
	hasGzip = strings.Contains(s, "GZIP")
	return
}

func DownloadRemoteDirs(i Instance, client *goph.Client) error {
	return downloadRemoteDirs(i, client, rsyncUsable(i, client))
}

func downloadRemoteDirs(i Instance, client *goph.Client, useRsync bool) error {
	hostname := i.IP
	if i.Hostname != "" {
		hostname = i.Hostname
	}
	hostComponent := safepath.SanitizeComponent(hostname)
	localBase, err := safepath.EnsureDirBelow("output", filepath.Join("downloads", hostComponent), 0o700)
	if err != nil {
		return fmt.Errorf("failed to create local download dir: %w", err)
	}

	if useRsync {
		logger.DebugExtra(i, "using rsync for downloads")
	}

	// Probe remote tar/gzip once so the fallback path never retries methods we
	// already know are unavailable.
	hasTar, hasGzip := probeRemote(client)
	logger.Debug(fmt.Sprintf("Remote probe %s: tar=%v gzip=%v", i.IP, hasTar, hasGzip))

	var wg sync.WaitGroup
	results := make(chan error, len(*DownloadDirs))
	sem := make(chan struct{}, max(1, *Threads))
	for _, entry := range *DownloadDirs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(e string) {
			defer wg.Done()
			defer func() { <-sem }()
			remote, extractDir, err := parseDownloadEntry(e, localBase)
			if err != nil {
				results <- err
				return
			}
			release, err := reserveDownloadArtifact(extractDir, remote)
			if err != nil {
				results <- err
				return
			}
			defer release()
			results <- downloadEntry(i, client, remote, extractDir, useRsync, hasTar, hasGzip)
		}(entry)
	}
	wg.Wait()
	close(results)
	var errs []error
	for err := range results {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// downloadEntry fetches one remote path, preferring rsync and falling back to
// the streaming-tar (or SFTP) transfer if rsync is unusable or errors.
func downloadEntry(i Instance, client *goph.Client, remote, extractDir string, useRsync, hasTar, hasGzip bool) error {
	return runTransferOperation("download "+remote, func(ctx context.Context) error {
		return downloadEntryContext(ctx, i, client, remote, extractDir, useRsync, hasTar, hasGzip)
	})
}

func downloadEntryContext(ctx context.Context, i Instance, client *goph.Client, remote, extractDir string, useRsync, hasTar, hasGzip bool) error {
	var rsyncErr error
	if useRsync {
		logger.InfoExtra(i, fmt.Sprintf("Downloading %s -> %s (rsync)", remote, extractDir))
		if err := rsyncDownload(ctx, i, client, extractDir, remote); err == nil {
			logger.InfoExtra(i, fmt.Sprintf("Downloaded %s (rsync)", remote))
			return nil
		} else {
			rsyncErr = err
			if errors.Is(err, errUnsafeRemoteTree) {
				logger.ErrExtra(i, fmt.Sprintf("refusing unsafe download %q: %s", remote, err))
				return err
			}
			if cleanupErr := removePartialDownload(extractDir, remote); cleanupErr != nil {
				return errors.Join(rsyncErr, fmt.Errorf("failed to clear partial rsync download: %w", cleanupErr))
			}
			logger.InfoExtra(i, fmt.Sprintf("rsync download of '%s' failed; trying built-in transfer", remote))
		}
	}
	if hasTar {
		if err := downloadSingleStream(ctx, i, client, remote, extractDir, hasGzip); err != nil {
			return errors.Join(rsyncErr, err)
		}
		return nil
	}
	logger.InfoExtra(i, "No tar on remote, using SFTP fallback")
	if err := downloadFallbackSFTP(ctx, i, client, remote, extractDir); err != nil {
		return fmt.Errorf("SFTP fallback for %q failed; partial local content may have been retained: %w", remote, errors.Join(rsyncErr, err))
	}
	if err := hardenDownloadedArtifact(downloadArtifactPath(extractDir, pathpkg.Clean(remote))); err != nil {
		return fmt.Errorf("downloaded SFTP tree is not portable/safe: %w", err)
	}
	logger.InfoExtra(i, fmt.Sprintf("Downloaded %s (SFTP fallback)", remote))
	return nil
}

// reserveDownloadArtifact prevents overlapping entries (for example /a/log
// and /b/log) from writing the same local tree concurrently. Existing content
// is rejected rather than merged or replaced.
func reserveDownloadArtifact(extractDir, remotePath string) (func(), error) {
	cleanRemote, err := normalizeRemoteDownloadPath(remotePath)
	if err != nil {
		return nil, err
	}
	target := downloadArtifactPath(extractDir, cleanRemote)
	if cleanRemote == "/" {
		entries, err := os.ReadDir(extractDir)
		if err != nil {
			return nil, err
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf("refusing to merge remote root into nonempty destination %q", extractDir)
		}
	} else if _, err := os.Lstat(target); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing download %q", target)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	target, err = filepath.Abs(filepath.Clean(target))
	if err != nil {
		return nil, err
	}
	downloadReservationMu.Lock()
	for reserved := range downloadReservations {
		if localPathsOverlap(reserved, target) {
			downloadReservationMu.Unlock()
			return nil, fmt.Errorf("download destination collision at %q", target)
		}
	}
	downloadReservations[target] = struct{}{}
	downloadReservationMu.Unlock()
	return func() {
		downloadReservationMu.Lock()
		delete(downloadReservations, target)
		downloadReservationMu.Unlock()
	}, nil
}

func localPathsOverlap(first, second string) bool {
	if first == second {
		return true
	}
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// removePartialDownload is safe here because reserveDownloadArtifact proved
// the destination absent (or empty for remote /) and holds the process-local
// reservation until all fallback attempts finish.
func removePartialDownload(extractDir, remotePath string) error {
	cleanRemote, err := normalizeRemoteDownloadPath(remotePath)
	if err != nil {
		return err
	}
	if cleanRemote != "/" {
		return os.RemoveAll(downloadArtifactPath(extractDir, cleanRemote))
	}
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		errs = append(errs, os.RemoveAll(filepath.Join(extractDir, entry.Name())))
	}
	return errors.Join(errs...)
}

// parseDownloadEntry splits "remote;local" and resolves the local extraction dir.
func parseDownloadEntry(entry string, localBase string) (remotePath, extractDir string, err error) {
	remotePath = strings.TrimSpace(entry)
	localDest := "."
	if idx := strings.Index(entry, ";"); idx != -1 {
		remotePath = strings.TrimSpace(entry[:idx])
		localDest = strings.TrimSpace(entry[idx+1:])
		if localDest == "" {
			return "", "", errors.New("local download destination is empty")
		}
	}
	if remotePath == "" {
		return "", "", errors.New("remote download path is empty")
	}
	if localDest == "." {
		info, statErr := os.Lstat(localBase)
		if statErr != nil {
			return "", "", fmt.Errorf("failed to inspect download destination %q: %w", localBase, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", "", fmt.Errorf("download destination %q is not a real directory", localBase)
		}
		extractDir = localBase
		return remotePath, extractDir, nil
	}
	extractDir, err = safepath.EnsureDirBelow(localBase, localDest, 0o700)
	if err != nil {
		return "", "", fmt.Errorf("unsafe local download destination %q: %w", localDest, err)
	}
	return remotePath, extractDir, nil
}

// batchFallbackIndividual streams each path one-by-one when the batch tar fails.
// downloadSingleStream downloads one remote path via streaming tar.
// Skips methods known unavailable from probe — no wasted attempts.
func downloadSingleStream(ctx context.Context, i Instance, client *goph.Client, remotePath string, extractDir string, hasGzip bool) error {
	cleanPath, err := normalizeRemoteDownloadPath(remotePath)
	if err != nil {
		return err
	}
	parentDir := pathpkg.Dir(cleanPath)
	baseName := pathpkg.Base(cleanPath)
	artifactRoot := downloadArtifactPath(extractDir, cleanPath)
	logger.InfoExtra(i, fmt.Sprintf("Downloading %s -> %s", remotePath, extractDir))

	// 1) Uncompressed tar — fastest on LAN, works everywhere tar exists
	// cd into parent dir so tar entries use only the basename
	// e.g. /root/.cache/backups -> cd /root/.cache && tar cf - backups
	cmd := remoteTarCommand(parentDir, baseName, false)
	var methodErrs []error
	if err := errors.Join(streamPortableTarOverSSH(ctx, client, cmd, extractDir, false), hardenDownloadedArtifact(artifactRoot)); err == nil {
		logger.InfoExtra(i, fmt.Sprintf("Downloaded %s", remotePath))
		return nil
	} else {
		methodErrs = append(methodErrs, fmt.Errorf("tar stream: %w", err))
		if cleanupErr := removePartialDownload(extractDir, cleanPath); cleanupErr != nil {
			return fmt.Errorf("tar failed and partial download could not be cleared: %w", errors.Join(err, cleanupErr))
		}
	}

	// 2) Compressed — only if gzip exists (probe told us)
	if hasGzip {
		cmd = remoteTarCommand(parentDir, baseName, true)
		if err := errors.Join(streamPortableTarOverSSH(ctx, client, cmd, extractDir, true), hardenDownloadedArtifact(artifactRoot)); err == nil {
			logger.InfoExtra(i, fmt.Sprintf("Downloaded %s (gzip)", remotePath))
			return nil
		} else {
			methodErrs = append(methodErrs, fmt.Errorf("gzip tar stream: %w", err))
			if cleanupErr := removePartialDownload(extractDir, cleanPath); cleanupErr != nil {
				return fmt.Errorf("gzip tar failed and partial download could not be cleared: %w", errors.Join(err, cleanupErr))
			}
		}
	}

	// 3) SFTP file-based fallback — last resort
	if err := downloadFallbackSFTP(ctx, i, client, remotePath, extractDir); err != nil {
		methodErrs = append(methodErrs, fmt.Errorf("SFTP: %w", err))
		return fmt.Errorf("all download methods failed for %q; partial local content may have been retained: %w", remotePath, errors.Join(methodErrs...))
	}
	logger.InfoExtra(i, fmt.Sprintf("Downloaded %s (SFTP fallback)", remotePath))
	return nil
}

func remoteTarCommand(parentDir, baseName string, gzipOutput bool) string {
	operand := "./" + baseName
	if !gzipOutput {
		return shWrap("cd " + shQuote(parentDir) + " && tar cf - " + shQuote(operand) + " 2>/dev/null")
	}
	cmd := "status=$(mktemp /tmp/coordinate-tar-status.XXXXXXXXXX) || exit 1; " +
		"trap 'rm -f -- \"$status\"' 0 HUP INT TERM; cd " + shQuote(parentDir) + " || exit 1; " +
		"(tar cf - " + shQuote(operand) + " 2>/dev/null; printf '%s\\n' \"$?\" > \"$status\") | gzip; " +
		"gzip_rc=$?; tar_rc=$(cat \"$status\" 2>/dev/null); " +
		"[ \"$gzip_rc\" -eq 0 ] && [ \"$tar_rc\" -eq 0 ]"
	return shWrap(cmd)
}

// streamTarOverSSH pipes a remote tar command's stdout directly into a local
// tar extractor. 64KB buffered I/O for throughput. No temp files anywhere.
func streamPortableTarOverSSH(ctx context.Context, client *goph.Client, remoteCmd string, extractDir string, isGzipped bool) error {
	return streamTarOverSSHMode(ctx, client, remoteCmd, extractDir, isGzipped, true)
}

func streamTarOverSSHMode(ctx context.Context, client *goph.Client, remoteCmd string, extractDir string, isGzipped, portableNames bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := newSessionContext(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}
	stopWatcher := closeOnContext(ctx, func() error {
		_ = client.Close()
		return session.Close()
	})
	defer stopWatcher()

	// 64KB buffered reader — reduces syscall overhead on the SSH channel
	buffered := bufio.NewReaderSize(stdout, 64*1024)

	var extractErr error
	if isGzipped && portableNames {
		extractErr = utils.ExtractPortableTarGzFromReader(buffered, extractDir)
	} else if isGzipped {
		extractErr = utils.ExtractTarGzFromReader(buffered, extractDir)
	} else if portableNames {
		extractErr = utils.ExtractPortableTarFromReader(buffered, extractDir)
	} else {
		extractErr = utils.ExtractTarFromReader(buffered, extractDir)
	}

	if extractErr != nil {
		// Stop the producer before returning. A rejected link or malformed archive
		// may leave unread stdout and otherwise deadlock session.Wait.
		_ = session.Close()
		return fmt.Errorf("extraction error: %w", extractErr)
	}
	if sessionErr := session.Wait(); sessionErr != nil {
		return fmt.Errorf("remote archive command failed: %w", sessionErr)
	}
	return nil
}

// remoteReadFS is the narrow read-only surface required by the recursive SFTP
// fallback. Function fields keep the traversal independently testable without
// an SSH server.
type remoteReadFS struct {
	lstat   func(string) (os.FileInfo, error)
	readDir func(string) ([]os.FileInfo, error)
	open    func(string) (io.ReadCloser, error)
}

// downloadFallbackSFTP recursively downloads directly through SFTP. It does
// not invoke tar, so this path works on minimal hosts. Links are rejected to
// match the hardened tar extractor's explicit policy.
func downloadFallbackSFTP(ctx context.Context, i Instance, client *goph.Client, remotePath string, extractDir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	logger.InfoExtra(i, fmt.Sprintf("SFTP fallback: %s -> %s", remotePath, extractDir))
	ftp, err := newSFTPContext(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to start SFTP subsystem: %w", err)
	}
	defer ftp.Close()
	stopWatcher := closeOnContext(ctx, func() error {
		_ = client.Close()
		return ftp.Close()
	})
	defer stopWatcher()
	fs := remoteReadFS{
		lstat:   ftp.Lstat,
		readDir: ftp.ReadDir,
		open: func(path string) (io.ReadCloser, error) {
			return ftp.Open(path)
		},
	}
	return downloadSFTPTree(ctx, fs, remotePath, extractDir)
}

func downloadSFTPTree(ctx context.Context, fs remoteReadFS, remotePath, extractDir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cleanRemote, err := normalizeRemoteDownloadPath(remotePath)
	if err != nil {
		return err
	}
	base := pathpkg.Base(cleanRemote)
	if cleanRemote != "/" {
		if err := validateSFTPName(base); err != nil {
			return fmt.Errorf("invalid remote root %q: %w", remotePath, err)
		}
	}
	root, err := prepareSFTPDownloadRoot(extractDir)
	if err != nil {
		return err
	}
	if cleanRemote == "/" {
		info, err := fs.lstat(cleanRemote)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("remote root is not a real directory")
		}
		entries, err := fs.readDir(cleanRemote)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := validateSFTPName(entry.Name()); err != nil {
				return err
			}
			if err := downloadSFTPNode(ctx, fs, pathpkg.Join(cleanRemote, entry.Name()), filepath.Join(root, safepath.SanitizeComponent(entry.Name()))); err != nil {
				return fmt.Errorf("SFTP tree incomplete; downloaded content retained: %w", err)
			}
		}
		return nil
	}
	if err := downloadSFTPNode(ctx, fs, cleanRemote, filepath.Join(root, safepath.SanitizeComponent(base))); err != nil {
		return fmt.Errorf("SFTP tree incomplete; downloaded content retained: %w", err)
	}
	return nil
}

func normalizeRemoteDownloadPath(remotePath string) (string, error) {
	trimmed := strings.TrimSpace(remotePath)
	if trimmed == "" {
		return "", errors.New("remote download path is empty")
	}
	return pathpkg.Clean(trimmed), nil
}

func downloadArtifactPath(extractDir, cleanRemote string) string {
	if cleanRemote == "/" || cleanRemote == "." {
		return extractDir
	}
	return filepath.Join(extractDir, safepath.SanitizeComponent(pathpkg.Base(cleanRemote)))
}

// hardenDownloadedArtifact makes collected data owner-only regardless of the
// source host's modes or the process umask. Links and special files are never
// chmodded because doing so could affect a target outside the download tree.
func hardenDownloadedArtifact(root string) error {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	seen := make(map[string]string)
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing downloaded link %q", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		key := strings.ToLower(filepath.ToSlash(rel))
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("portable download name collision between %q and %q", previous, path)
		}
		seen[key] = path
		switch {
		case info.IsDir():
			return os.Chmod(path, 0o700)
		case info.Mode().IsRegular():
			return os.Chmod(path, 0o600)
		default:
			return fmt.Errorf("refusing downloaded special file %q", path)
		}
	})
}

func downloadSFTPNode(ctx context.Context, fs remoteReadFS, remotePath, localPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := fs.lstat(remotePath)
	if err != nil {
		return fmt.Errorf("failed to inspect remote path %q: %w", remotePath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("remote link %q is unsupported", remotePath)
	}
	if info.IsDir() {
		if err := ensureSFTPDownloadDir(localPath); err != nil {
			return fmt.Errorf("failed to create local directory %q: %w", localPath, err)
		}
		entries, err := fs.readDir(remotePath)
		if err != nil {
			return fmt.Errorf("failed to list remote directory %q: %w", remotePath, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if err := validateSFTPName(name); err != nil {
				return fmt.Errorf("invalid entry in %q: %w", remotePath, err)
			}
			if err := downloadSFTPNode(ctx, fs, pathpkg.Join(remotePath, name), filepath.Join(localPath, safepath.SanitizeComponent(name))); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("remote special file %q (%s) is unsupported", remotePath, info.Mode())
	}
	return copySFTPFile(ctx, fs, remotePath, localPath)
}

func validateSFTPName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return fmt.Errorf("unsafe filename %q", name)
	}
	return nil
}

func prepareSFTPDownloadRoot(root string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("failed to resolve SFTP destination: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("SFTP destination is not a real directory")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	} else if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return "", err
	}
	return abs, nil
}

func ensureSFTPDownloadDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return os.Mkdir(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("destination directory is a symlink")
	}
	if !info.IsDir() {
		return errors.New("destination directory is not a directory")
	}
	return os.Chmod(dir, 0o700)
}

func copySFTPFile(ctx context.Context, fs remoteReadFS, remotePath, localPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if existing, err := os.Lstat(localPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing destination %q (%s)", localPath, existing.Mode())
	} else if !os.IsNotExist(err) {
		return err
	}

	remote, err := fs.open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file %q: %w", remotePath, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(localPath), ".coordinate-sftp-*")
	if err != nil {
		_ = remote.Close()
		return fmt.Errorf("failed to create local temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	stopWatcher := closeOnContext(ctx, func() error {
		_ = remote.Close()
		return tmp.Close()
	})
	defer stopWatcher()
	copyErr := error(nil)
	if _, err := io.Copy(tmp, remote); err != nil {
		copyErr = fmt.Errorf("failed to copy %q: %w", remotePath, err)
	}
	remoteCloseErr := remote.Close()
	syncErr := tmp.Sync()
	chmodErr := tmp.Chmod(0o600)
	closeErr := tmp.Close()
	if err := errors.Join(copyErr, remoteCloseErr, syncErr, chmodErr, closeErr); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := replaceDownloadedFile(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to install local file %q: %w", localPath, err)
	}
	return nil
}

func Upload(client *goph.Client, localPath string, remotePath string) error {
	logger.Debug(fmt.Sprintf("Starting Upload. Local path: %s, Remote path: %s", localPath, remotePath))

	scp_client, err := scp.NewClientBySSH(client.Client)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to initialize SCP client: %s", err))
		return err
	}

	f, err := os.Open(localPath)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to open local file: %s", err))
		return err
	}
	defer f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), payloadTimeout())
	defer cancel()
	err = scp_client.CopyFromFile(ctx, *f, remotePath, "0700")
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to SCP file: %s", err))
		return err
	}

	output, err := boundedCommand(client, probeCommandTimeout, shWrap("test -f "+shQuote(remotePath)+" && printf '%s\\n' present"))
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to verify remote file: %s", err))
		return err
	}
	if !strings.Contains(string(output), "present") {
		logger.Err("Remote file does not exist after upload.")
		return errors.New("upload failed: remote file missing")
	}
	logger.Debug("Upload successful.")
	return nil
}
