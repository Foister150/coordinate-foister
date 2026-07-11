package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/logrusorgru/aurora"
	. "github.com/mattn/go-colorable"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/safepath"
)

const outputRoot = "output"

var (
	stdoutLogger *log.Logger
	stderrLogger *log.Logger
	tabs         string
)

var (
	instancePasswordPattern = regexp.MustCompile(`(?i)(\bPassword:).*?(\s+(?:Script|Port|Outfile|Hostname):|})`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)(\b[A-Z0-9_]*(?:PASS(?:WORD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*)([^;\r\n]*)`)
	passwordValuePattern    = regexp.MustCompile(`(?i)(\bpassword\s*[:=]\s*)([^,;\r\n}]*)`)
	commandSecretPattern    = regexp.MustCompile(`(?i)(--?(?:password|pass|secret|token|api[_-]?key)\s+)(\S+)`)
	sensitiveEnvPatterns    []*regexp.Regexp
	outputReservations      sync.Map
)

func InitLogger() {
	InitLoggerWithWriters(NewColorableStdout(), NewColorableStderr())
}

// InitLoggerWithWriters makes stream behavior deterministic in tests while
// production continues to use color-aware stdout and stderr writers.
func InitLoggerWithWriters(stdout, stderr io.Writer) {
	stdoutLogger = log.New(stdout, "", 0)
	stderrLogger = log.New(stderr, "", 0)
}

func ensureLoggers() {
	if stdoutLogger == nil || stderrLogger == nil {
		InitLogger()
	}
}

func Tabber(tabnum int) {
	tabs = ""
	for i := 0; i < tabnum; i++ {
		tabs += "\t"
	}
}

func Time() string {
	return time.Now().Format("03:04:05PM")
}

// SetSensitiveEnvironment registers the environment keys supplied by the CLI
// and env file. Their values are then removed even when a downstream debug
// message contains the fully assembled remote command.
func SetSensitiveEnvironment(assignments []string) {
	patterns := make([]*regexp.Regexp, 0, len(assignments))
	for _, assignment := range assignments {
		key, _, found := strings.Cut(assignment, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		patterns = append(patterns, regexp.MustCompile(`(?m)(\b`+regexp.QuoteMeta(key)+`\s*=\s*)([^\r\n]*)`))
	}
	sensitiveEnvPatterns = patterns
}

// RedactSecrets is a final safety net for structured values accidentally sent
// to the logger. Callers should still avoid formatting credentials in the first
// place because arbitrary unlabelled values cannot be identified reliably.
func RedactSecrets(value string) string {
	value = passwordValuePattern.ReplaceAllString(value, `${1}[REDACTED]`)
	value = commandSecretPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	value = instancePasswordPattern.ReplaceAllString(value, `${1}[REDACTED]${2}`)
	value = secretAssignmentPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	for _, pattern := range sensitiveEnvPatterns {
		value = pattern.ReplaceAllString(value, `${1}[REDACTED]`)
	}
	return value
}

func formattedLine(a ...interface{}) string {
	safe := make([]interface{}, len(a))
	for index, value := range a {
		switch instance := value.(type) {
		case Instance:
			instance.Password = "[REDACTED]"
			safe[index] = instance
		case *Instance:
			if instance == nil {
				safe[index] = instance
				continue
			}
			copy := *instance
			copy.Password = "[REDACTED]"
			safe[index] = &copy
		default:
			safe[index] = value
		}
	}
	return RedactSecrets(fmt.Sprintln(safe...))
}

func stdoutPayloadEnabled() bool {
	return ActiveOutputMode != OutputErrorsOnly
}

func errorsEnabled() bool {
	return ActiveOutputMode != OutputSuperQuiet
}

func normalEnabled() bool {
	return ActiveOutputMode == OutputNormal || ActiveOutputMode == OutputDebug
}

// Status writes unprefixed operator summaries in normal and debug modes.
func Status(a ...interface{}) {
	if !normalEnabled() {
		return
	}
	ensureLoggers()
	stdoutLogger.Print(RedactSecrets(fmt.Sprint(a...)))
}

// ReserveOutput validates and claims a payload's final path before the remote
// payload starts. The process-wide claim catches cross-host and concurrent
// collisions; an existing file is always an error rather than an overwrite.
func ReserveOutput(i Instance) error {
	if i.Outfile == "" {
		return nil
	}
	target, err := safepath.ResolveBelow(outputRoot, i.Outfile)
	if err != nil {
		return fmt.Errorf("unsafe output path %q: %w", i.Outfile, err)
	}
	rootAbs, err := filepath.Abs(outputRoot)
	if err != nil {
		return err
	}
	parentRel, err := filepath.Rel(rootAbs, filepath.Dir(target))
	if err != nil {
		return err
	}
	if parentRel != "." {
		if _, err := safepath.EnsureDirBelow(outputRoot, parentRel, 0o700); err != nil {
			return fmt.Errorf("unsafe output directory: %w", err)
		}
	} else {
		// Ensure the root itself exists and is not a symlink.
		if _, err := safepath.EnsureDirBelow(".", outputRoot, 0o700); err != nil {
			return fmt.Errorf("unsafe output directory: %w", err)
		}
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %q", target)
	} else if !os.IsNotExist(err) {
		return err
	}
	owner := fmt.Sprintf("%d\x00%s\x00%s\x00%d\x00%s", i.OutputOwner, i.IP, i.Username, i.ID, i.Outfile)
	actual, loaded := outputReservations.LoadOrStore(target, owner)
	if loaded && actual.(string) != owner {
		return fmt.Errorf("output path collision at %q", target)
	}
	return nil
}

// Stdout emits payload output and, when configured, persists it atomically.
// The returned error lets execution accounting distinguish a successful remote
// command from a failed local result write.
func Stdout(i Instance, a ...interface{}) error {
	ensureLoggers()
	if stdoutPayloadEnabled() {
		stdoutLogger.Printf("%s%s:%s%s\n%s", tabs, BrightCyan("[STDOUT"), Summary(i), BrightCyan("]"), formattedLine(a...))
	}

	if i.Outfile == "" {
		return nil
	}
	return SaveOutput(i, []byte(fmt.Sprint(a...)))
}

// SaveOutput persists payload bytes without emitting a terminal STDOUT block.
// It is used for successful commands that produced no output so every requested
// -o artifact exists and local persistence failures remain visible to metrics.
func SaveOutput(i Instance, data []byte) error {
	if i.Outfile == "" {
		return nil
	}
	if err := ReserveOutput(i); err != nil {
		return err
	}
	if err := safepath.AtomicWriteExclusive(outputRoot, i.Outfile, data, 0o600); err != nil {
		return err
	}
	return nil
}

func Stderr(i Instance, a ...interface{}) {
	if ActiveOutputMode == OutputSuperQuiet {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s:%s%s\n%s", tabs, BrightRed("[STDERR"), Summary(i), BrightRed("]"), formattedLine(a...))
}

func Crit(i Instance, a ...interface{}) {
	if !errorsEnabled() {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s:%s%s %s", tabs, Red("[CRIT"), Summary(i), Red("]"), formattedLine(a...))
}

func Err(a ...interface{}) {
	if !errorsEnabled() {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s %s", tabs, BrightRed("[ERROR]"), formattedLine(a...))
}

func ErrExtra(i Instance, a ...interface{}) {
	if !errorsEnabled() {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s:%s%s %s", tabs, BrightRed("[ERROR"), Summary(i), BrightRed("]"), formattedLine(a...))
}

func Fatal(a ...interface{}) {
	ensureLoggers()
	stderrLogger.Printf("%s%s %s", tabs, BrightRed("[FATAL]"), formattedLine(a...))
	os.Exit(1)
}

func Warning(a ...interface{}) {
	if !normalEnabled() {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s %s", tabs, Yellow("[WARN]"), formattedLine(a...))
}

func Info(a ...interface{}) {
	if !normalEnabled() {
		return
	}
	ensureLoggers()
	stdoutLogger.Printf("%s%s %s", tabs, BrightCyan("[INFO]"), formattedLine(a...))
}

func InfoExtra(i Instance, a ...interface{}) {
	if !normalEnabled() {
		return
	}
	ensureLoggers()
	stdoutLogger.Printf("%s%s:%s%s %s", tabs, BrightCyan("[INFO"), Summary(i), BrightCyan("]"), formattedLine(a...))
}

func Debug(a ...interface{}) {
	if ActiveOutputMode != OutputDebug {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s %s", tabs, Cyan("[DEBUG]"), formattedLine(a...))
}

func DebugExtra(i Instance, a ...interface{}) {
	if ActiveOutputMode != OutputDebug {
		return
	}
	ensureLoggers()
	stderrLogger.Printf("%s%s:%s%s %s", tabs, Cyan("[DEBUG"), Summary(i), Cyan("]"), formattedLine(a...))
}

func Summary(i Instance) string {
	username := safepath.SanitizeComponent(i.Username)
	ip := safepath.SanitizeComponent(i.IP)
	if i.Script == "" {
		return fmt.Sprintf("%d:%s:%s", Blue(i.ID), BrightRed(username), BrightGreen(ip))
	}
	scriptLabel := RedactSecrets(i.Script)
	if strings.HasPrefix(scriptLabel, "command: ") {
		scriptLabel = "command"
	}
	scriptLabel = safepath.SanitizeComponent(scriptLabel)
	hostname := safepath.SanitizeComponent(i.Hostname)
	return fmt.Sprintf("%d@%s:%s:%s:%s/%s", Blue(i.ID), Time(), BrightRed(username), BrightGreen(ip), BrightGreen(hostname), BrightBlue(scriptLabel))
}
