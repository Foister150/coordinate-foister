package globals

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"inet.af/netaddr"

	flag "github.com/spf13/pflag"
)

const AgentKeyFlagValue = "ssh-agent"

const (
	MaxSSHPort            = 65_535
	MaxPayloadConcurrency = 1_024
	MaxHostConcurrency    = 4_096
	MaxTargetExpansion    = int64(1_048_576)
	MaxTransferTimeout    = 86_400 // seconds (24 hours)
)

var DefaultTmpDir = filepath.Join(os.TempDir(), "coordinate")

type OutputMode uint8

const (
	OutputNormal OutputMode = iota
	OutputQuiet
	OutputDebug
	OutputSuperQuiet
	OutputErrorsOnly
)

// SelectOutputMode resolves conflicting output flags from strongest filtering
// to weakest: errors-only, super-quiet, debug, quiet, then normal.
func SelectOutputMode(errorsOnly, superQuiet, debug, quiet bool) OutputMode {
	switch {
	case errorsOnly:
		return OutputErrorsOnly
	case superQuiet:
		return OutputSuperQuiet
	case debug:
		return OutputDebug
	case quiet:
		return OutputQuiet
	default:
		return OutputNormal
	}
}

type Instance struct {
	ID       int
	IP       string
	Username string
	Password string
	Script   string
	Port     int
	Outfile  string
	Hostname string
	// OutputOwner uniquely identifies one host job so duplicate config entries
	// cannot mistake each other's preflight reservation for their own.
	OutputOwner uint64
}

var (
	Timeout          time.Duration
	TransferTimeout  time.Duration
	ActiveOutputMode = OutputNormal
)

type OperationResult struct {
	Kind  string
	Label string
	Err   error
}

type HostWorkResult struct {
	PayloadsRequested  int
	TransfersRequested int
	Payloads           []OperationResult
	Transfers          []OperationResult
	Failures           []error
}

func (r HostWorkResult) Error() error {
	errs := append([]error(nil), r.Failures...)
	for _, operation := range r.Payloads {
		errs = append(errs, operation.Err)
	}
	for _, operation := range r.Transfers {
		errs = append(errs, operation.Err)
	}
	if len(r.Payloads) != r.PayloadsRequested {
		errs = append(errs, errors.New("not all requested payloads were attempted"))
	}
	if len(r.Transfers) != r.TransfersRequested {
		errs = append(errs, errors.New("not all requested transfer phases were attempted"))
	}
	return errors.Join(errs...)
}

func (r HostWorkResult) Successful() bool { return r.Error() == nil }

type HostResult struct {
	Host          string
	Username      string
	AuthAttempts  int
	Authenticated bool
	AuthErr       error
	Work          HostWorkResult
}

func (r HostResult) Successful() bool {
	return r.Authenticated && r.AuthErr == nil && r.Work.Successful()
}

type RunSummary struct {
	HostsAttempted      int
	HostsAuthenticated  int
	HostsSucceeded      int
	HostsFailed         int
	AuthenticationTries int
	PayloadsRequested   int
	PayloadsAttempted   int
	PayloadsSucceeded   int
	PayloadsFailed      int
	PayloadsTimedOut    int
	PayloadsSkipped     int
	TransfersRequested  int
	TransfersAttempted  int
	TransfersSucceeded  int
	TransfersFailed     int
	TransfersSkipped    int
	FailedHosts         []string
}

var (
	resultMu    sync.Mutex
	hostResults []HostResult
)

func RecordHostResult(result HostResult) {
	resultMu.Lock()
	hostResults = append(hostResults, result)
	resultMu.Unlock()
}

func HostResultsSnapshot() []HostResult {
	resultMu.Lock()
	defer resultMu.Unlock()
	return append([]HostResult(nil), hostResults...)
}

func ResetHostResults() {
	resultMu.Lock()
	hostResults = nil
	resultMu.Unlock()
}

func SummarizeHostResults() RunSummary {
	results := HostResultsSnapshot()
	summary := RunSummary{HostsAttempted: len(results)}
	for _, result := range results {
		summary.AuthenticationTries += result.AuthAttempts
		if result.Authenticated {
			summary.HostsAuthenticated++
		}
		if result.Successful() {
			summary.HostsSucceeded++
		} else {
			summary.HostsFailed++
			summary.FailedHosts = append(summary.FailedHosts, result.Host)
		}
		summary.PayloadsRequested += result.Work.PayloadsRequested
		summary.TransfersRequested += result.Work.TransfersRequested
		for _, operation := range result.Work.Payloads {
			summary.PayloadsAttempted++
			if operation.Err == nil {
				summary.PayloadsSucceeded++
			} else {
				summary.PayloadsFailed++
				if errors.Is(operation.Err, context.DeadlineExceeded) {
					summary.PayloadsTimedOut++
				}
			}
		}
		if missing := result.Work.PayloadsRequested - len(result.Work.Payloads); missing > 0 {
			summary.PayloadsSkipped += missing
		}
		for _, operation := range result.Work.Transfers {
			summary.TransfersAttempted++
			if operation.Err == nil {
				summary.TransfersSucceeded++
			} else {
				summary.TransfersFailed++
			}
		}
		if missing := result.Work.TransfersRequested - len(result.Work.Transfers); missing > 0 {
			summary.TransfersSkipped += missing
		}
	}
	return summary
}

var (
	Port              = flag.IntP("port", "P", 22, "SSH port to use (1..65535)")
	Threads           = flag.IntP("limit", "l", 3, "Max scripts/commands run concurrently on a single host (1..1024)")
	MaxHosts          = flag.IntP("max-hosts", "m", 100, "Max hosts processed concurrently (0 uses the absolute 4096-host safety ceiling)")
	MaxTargets        = flag.Int64("max-targets", 65_536, "Max target addresses expanded from ranges/CIDRs (1..1048576)")
	Timelimit         = flag.IntP("timeout", "T", 30, "Positive time limit in seconds per script or command")
	TransferTimelimit = flag.Int("transfer-timeout", 900, "Overall time limit in seconds per transfer (1..86400)")
	Targets           = flag.StringP("targets", "t", "", "List of target IP addresses or DNS names (ex., 127.0.0.1-127.0.0.5,192.168.1.0/24,host.example)")
	Usernames         = flag.StringP("usernames", "u", "", "List of usernames")
	Passwords         = flag.StringP("passwords", "p", "", "List of passwords")
	Callbacks         = flag.StringP("callbacks", "c", "", "Unavailable legacy password-helper option")
	Outfile           = flag.StringP("outfile-fmt", "o", "", "Output format. If not specified, then no output is saved.")
	Key               = flag.StringP("key", "k", "", "Use SSH agent with bare -k, or a private key with -k=PATH/--key=PATH")
	Environment       = flag.StringArrayP("env", "E", nil, "Set KEY=VALUE before running payloads (repeat for multiple variables)")
	TmpDir            = flag.StringP("tmpdir", "W", DefaultTmpDir, "Private directory for local temporary files")
	DownloadDirs      = flag.StringArrayP("download", "D", []string{}, "Download remote directory(s) to local output (e.g. -D /etc/ssh -D /var/log)")
	UploadFiles       = flag.StringArrayP("upload", "F", []string{}, "Upload local file/dir(s) to remote (e.g. -F 'local;remote' or -F ./tools;/tmp/tools)")
	Sudo              = flag.BoolP("sudo", "S", false, "Attempt to escalate through sudo, if not root")
	QuietOut          = flag.BoolP("quiet", "q", false, "Print only script output")
	SuperQuietOut     = flag.BoolP("super-quiet", "Q", false, "Print only script output, and no errors")
	DebugOut          = flag.BoolP("debug", "d", false, "Print debug messages")
	Errs              = flag.BoolP("errors", "e", false, "Print errors only (no stdout)")
	NoValidate        = flag.BoolP("no-validate", "n", false, "Don't ensure shell is valid, or that scripts have finished running")
	CreateConfig      = flag.StringP("create-config", "C", "", "Create a json config for auth. ONLY COMPATIBLE WITH password.sh. This has no error handling. Have fun.")
	IgnoreUsers       = flag.StringP("ignore-users", "I", "", "Unavailable legacy password-helper option")
	AllPass           = flag.StringP("all-pass", "A", "", "Unavailable legacy password-helper option")
	UseConfig         = flag.BoolP("use-config", "U", false, "Use config.json. This has no error handling. Have fun.")
	ConfigOnly        = flag.StringP("CO", "O", "", "Create a config from existing credentials without running password.sh. Pass the root password as value.")
	Command           = flag.StringArrayP("command", "x", []string{}, "Execute command(s) directly instead of scripts")
	ScheduledCommand  = flag.StringArray("schedule", []string{}, "Install command(s) as managed recurring cron jobs; requires --interval")
	ScheduleInterval  = flag.String("interval", "", "Recurring interval (Go duration syntax, e.g. 5m or 90m)")
	Scheduler         = flag.String("scheduler", "auto", "Scheduler for --schedule: auto, systemd, or cron")
	NoRsync           = flag.Bool("no-rsync", false, "Never use rsync for uploads/downloads; always use the built-in streaming/SFTP transfer")
	Scripts           = []string{}
	Commands          = []string{}
	ScheduledCommands = []string{}
	ScheduleEvery     time.Duration
	ScheduleBackend   string
	UsernameList      = []string{}
	PasswordList      = []string{}
	EnvironCmds       = []string{}
	Addresses         = []netaddr.IP{}
	StringAddresses   = []string{}
)

func init() {
	flag.Lookup("key").NoOptDefVal = AgentKeyFlagValue
}
