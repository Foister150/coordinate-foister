package cli

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/LanodonF/coordinate-foister/internal/config"
	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

var ErrHelp = flag.ErrHelp

func Init() error {
	logger.InitLogger()

	// Route --help through grouped usage and return parse errors to main so it
	// can use stderr and exit 2 without dumping the full reference text.
	flag.Usage = func() { PrintUsageTo(os.Stdout) }
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	normalizedArgs, err := normalizeOptionalKeyArgs(os.Args[1:])
	if err != nil {
		return err
	}
	os.Args = append([]string{os.Args[0]}, normalizedArgs...)
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return err
	}
	ActiveOutputMode = SelectOutputMode(*Errs, *SuperQuietOut, *DebugOut, *QuietOut)

	if err := validateNumericFlags(*Port, *Timelimit, *Threads, *MaxHosts, *MaxTargets, *TransferTimelimit); err != nil {
		return err
	}
	if strings.TrimSpace(*TmpDir) == "" {
		return fmt.Errorf("--tmpdir must not be empty")
	}

	Timeout = time.Duration(*Timelimit) * time.Second
	TransferTimeout = time.Duration(*TransferTimelimit) * time.Second

	Scripts = flag.Args()
	Commands = *Command

	*TmpDir = filepath.Clean(*TmpDir)
	if err := ensurePrivateDir(*TmpDir, !flag.CommandLine.Changed("tmpdir")); err != nil {
		return fmt.Errorf("prepare temporary directory %q: %w", *TmpDir, err)
	}
	if err := ensurePrivateDir("output", true); err != nil {
		return fmt.Errorf("prepare output directory: %w", err)
	}
	return nil
}

func validateNumericFlags(port, timeoutSeconds, perHostLimit, maxHosts int, maxTargets int64, transferTimeoutSeconds int) error {
	if port < 1 || port > MaxSSHPort {
		return fmt.Errorf("--port must be between 1 and %d", MaxSSHPort)
	}
	if timeoutSeconds <= 0 {
		return fmt.Errorf("--timeout must be greater than zero")
	}
	// time.Duration is an int64 count of nanoseconds. Validate before the
	// conversion/multiplication so very large values cannot wrap into an
	// immediate or negative timeout on 64-bit systems.
	if int64(timeoutSeconds) > int64(math.MaxInt64)/int64(time.Second) {
		return fmt.Errorf("--timeout is too large")
	}
	if transferTimeoutSeconds <= 0 {
		return fmt.Errorf("--transfer-timeout must be greater than zero")
	}
	if int64(transferTimeoutSeconds) > int64(math.MaxInt64)/int64(time.Second) {
		return fmt.Errorf("--transfer-timeout is too large")
	}
	if transferTimeoutSeconds > MaxTransferTimeout {
		return fmt.Errorf("--transfer-timeout must be between 1 and %d seconds", MaxTransferTimeout)
	}
	if perHostLimit < 1 || perHostLimit > MaxPayloadConcurrency {
		return fmt.Errorf("--limit must be between 1 and %d", MaxPayloadConcurrency)
	}
	if maxHosts < 0 || maxHosts > MaxHostConcurrency {
		return fmt.Errorf("--max-hosts must be between 0 and %d", MaxHostConcurrency)
	}
	if maxTargets < 1 || maxTargets > MaxTargetExpansion {
		return fmt.Errorf("--max-targets must be between 1 and %d", MaxTargetExpansion)
	}
	return nil
}

// ensurePrivateDir creates a directory tree with owner-only permissions. App-
// owned directories can be safely hardened when they already exist. An
// explicitly selected existing temp directory is instead checked and rejected
// when it is shared: changing permissions on a path such as /tmp would be a
// dangerous and surprising side effect.
func ensurePrivateDir(path string, hardenExisting bool) error {
	// Lstat is intentional: following a pre-created app-directory symlink would
	// redirect sensitive files and, for app-owned paths, chmod its target.
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path must not be a symbolic link")
		}
		if !info.IsDir() {
			return fmt.Errorf("path exists and is not a directory")
		}
		if !hardenExisting && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("existing directory permissions %04o allow group or other access", info.Mode().Perm())
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		hardenExisting = true
	default:
		return err
	}

	if hardenExisting {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("set owner-only permissions: %w", err)
		}
	}
	return nil
}

func normalizeOptionalKeyArgs(args []string) ([]string, error) {
	normalized := make([]string, 0, len(args))

	for _, arg := range args {
		switch {
		case len(arg) > 2 && strings.HasPrefix(arg, "-k") && !strings.HasPrefix(arg, "-k="):
			return nil, fmt.Errorf("ambiguous key option %q: bare -k uses ssh-agent; key paths require -k=PATH or --key=PATH", arg)
		default:
			normalized = append(normalized, arg)
		}
	}

	return normalized, nil
}

func InputCheck() error {
	if (len(Scripts) == 0 && len(Commands) == 0 && *CreateConfig == "" && *ConfigOnly == "" && len(*DownloadDirs) == 0 && len(*UploadFiles) == 0) || ((*Usernames == "" || *Targets == "") && !*UseConfig) {
		return fmt.Errorf("missing target(s), script(s)/command(s), and/or username(s)")
	}
	if *UseConfig && (*Usernames != "" || *Passwords != "" || flag.CommandLine.Changed("key") || *ConfigOnly != "" || *CreateConfig != "") {
		return fmt.Errorf("--use-config cannot be combined with manual authentication or config-mutation flags")
	}
	if *CreateConfig != "" {
		return fmt.Errorf("--create-config is unavailable because scripts/misc/password.sh is not bundled; use --CO to store credentials that authenticate successfully")
	}
	if err := validateLegacyHelperFlags(flag.CommandLine); err != nil {
		return err
	}

	// Ensure scripts and commands are mutually exclusive
	if len(Scripts) > 0 && len(Commands) > 0 {
		return fmt.Errorf("cannot specify both scripts and commands; use either scripts or --command")
	}
	if err := validateLocalInputs(Scripts, *UploadFiles); err != nil {
		return err
	}

	var err error
	EnvironCmds, err = config.ReadEnv(*Environment)
	if err != nil {
		return err
	}
	logger.SetSensitiveEnvironment(EnvironCmds)

	return nil
}

func validateLegacyHelperFlags(flags *flag.FlagSet) error {
	for _, name := range []string{"ignore-users", "all-pass", "callbacks"} {
		if flags.Changed(name) {
			return fmt.Errorf("--%s is unavailable because its legacy password helper is not bundled", name)
		}
	}
	return nil
}

// validateLocalInputs catches deterministic fleet-wide failures before any SSH
// authentication. Script contents are still loaded by the single-flight cache;
// this preflight only verifies type/readability and upload source existence.
func validateLocalInputs(scripts, uploads []string) error {
	for _, script := range scripts {
		info, err := os.Stat(script)
		if err != nil {
			return fmt.Errorf("script %q is unavailable: %w", script, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("script %q is not a regular file", script)
		}
		file, err := os.Open(script)
		if err != nil {
			return fmt.Errorf("script %q is not readable: %w", script, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close script %q after validation: %w", script, err)
		}
	}
	for _, entry := range uploads {
		parts := strings.SplitN(entry, ";", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid upload format %q; use local_path;remote_path", entry)
		}
		localPath := strings.TrimSpace(parts[0])
		info, err := os.Stat(localPath)
		if err != nil {
			return fmt.Errorf("local upload path %q is unavailable: %w", localPath, err)
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("local upload path %q must be a regular file or directory", localPath)
		}
	}
	return nil
}

// usageText is the hand-grouped help shown for -h/--help and on usage errors.
// It is kept in sync with the README so operators see the same reference in the
// terminal and the repo.
const usageText = `coordinate — parallel SSH remote management for sysadmin and CCDC-style work

USAGE
  coordinate [options] [script ...]
  coordinate -t <targets> -u <users> -p <passwords> <script.sh>
  coordinate -t <targets> -u <users> -x <command>
  coordinate -U [-t <targets>] [script ...]

  Scripts and direct commands (-x) are mutually exclusive. Scripts are uploaded,
  run once per host, then removed. Uploads/downloads run before execution.

TARGETING
  -t, --targets TARGETS   DNS names or IPs: singles, comma lists, ranges, CIDR
                          e.g. host.lan, 192.168.1.5, 192.168.1.10-20, 10.0.0.0/24
  -P, --port PORT         SSH port, 1..65535 (default 22)
  -m, --max-hosts N       max concurrent hosts, 0..4096 (default 100; 0 = safety ceiling)
      --max-targets N     max expanded addresses, 1..1048576 (default 65536)

AUTHENTICATION
  -u, --usernames USERS   comma-separated usernames to try
  -p, --passwords PASSES  comma-separated passwords to try (prompted if omitted)
  -k, --key[=PATH]        bare -k uses ssh-agent; key paths require -k=PATH
  -U, --use-config        use plaintext credentials from config.json

EXECUTION
  -x, --command COMMAND   run direct command(s) instead of scripts (repeatable)
  -E, --env KEY=VALUE     export an environment value; repeat for multiple values
  -S, --sudo              escalate via sudo when the SSH user is not root
  -T, --timeout SECONDS   positive time limit per script/command (default 30)
  -l, --limit N           per-host payload concurrency, 1..1024 (default 3)
  -n, --no-validate       skip the shell-usability probe before running

FILE TRANSFER (rsync when available, else built-in streaming/SFTP)
  -F, --upload LOCAL;REMOTE   upload a local file/dir to a remote path (repeatable)
  -D, --download REMOTE[;LOCAL]
                             LOCAL is relative beneath per-host output (repeatable)
  -W, --tmpdir DIR           private local temp dir (default: OS temp/coordinate)
      --transfer-timeout N   overall seconds per transfer, 1..86400 (default 900)
      --no-rsync             never use rsync; always use the built-in transfer

OUTPUT
  -o, --outfile-fmt FORMAT   safe no-overwrite output using %i% %h% %s%+index
  -q, --quiet                print only script output
  -Q, --super-quiet          print only script output, suppress errors
  -e, --errors               print errors only
  -d, --debug                print debug messages

  Combined-mode precedence: --errors, --super-quiet, --debug, --quiet, normal.

CONFIG HELPERS
  -O, --CO ROOTPASS       create a config entry from working credentials
  -C, --create-config P   unsupported: legacy password.sh helper is not bundled
  -I, -A, -c              unavailable legacy password-helper options

EXAMPLES
  Run a script across a range with a password list:
    coordinate -t 192.168.1.10-20 -u root -p 'pw1,pw2' ./audit.sh

  Run a command with ssh-agent keys across a /24:
    coordinate -t 10.10.1.0/24 -u admin -k -x 'hostname && whoami'

  Push a toolkit to a user-writable path, then inspect it with sudo:
    coordinate -t 172.16.1.15 -u ops -p 'secret' -S -F './tools;/tmp/tools' -x 'ls -la /tmp/tools'

  Pull remote logs into output/downloads/<host>/logs:
    coordinate -t 172.16.1.15 -u root -p 'secret' -D '/var/log;logs'

  Save per-host command output:
    coordinate -t 192.168.1.5 -u root -p 'secret' -o '%h%/%s%.txt' -x 'uname -a'

Only run against systems you own or are explicitly authorized to administer.
`

// PrintUsage writes the grouped help to stdout. WriteString avoids treating the
// %i%/%h%/%s% placeholders in the text as printf directives.
func PrintUsageTo(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

func PrintUsageError(w io.Writer, err error) {
	fmt.Fprintf(w, "Error: %v\n\nUsage: coordinate [options] [script ...]\nTry 'coordinate --help' for full help.\n", err)
}

func PrintUsage() {
	PrintUsageTo(os.Stdout)
}
