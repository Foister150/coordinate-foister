package ssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/melbahja/goph"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

type schedulerBackend string

const (
	schedulerAuto    schedulerBackend = "auto"
	schedulerSystemd schedulerBackend = "systemd"
	schedulerCron    schedulerBackend = "cron"
)

// cronExpression uses only comma-separated numeric fields, understood by the
// traditional crons used on BSD, Solaris, BusyBox/Alpine, and Linux. We avoid
// @hourly and step syntax because they are extensions, not portable crontab.
func cronExpression(interval time.Duration) (string, error) {
	if interval < time.Minute || interval > 24*time.Hour || interval%time.Minute != 0 || (24*time.Hour)%interval != 0 || (interval >= time.Hour && interval%time.Hour != 0) {
		return "", fmt.Errorf("unsupported recurring interval %s", interval)
	}
	minutes := int(interval / time.Minute)
	if minutes < 60 {
		return cronNumberList(0, 59, minutes) + " * * * *", nil
	}
	if minutes%60 != 0 {
		return "", fmt.Errorf("unsupported recurring interval %s", interval)
	}
	return "0 " + cronNumberList(0, 23, minutes/60) + " * * *", nil
}

func cronNumberList(first, last, step int) string {
	parts := make([]string, 0, (last-first)/step+1)
	for value := first; value <= last; value += step {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func scheduledCommandID(command string) string {
	sum := sha256.Sum256([]byte(command))
	return fmt.Sprintf("%x", sum[:8])
}

// scheduledInstallScript writes an owner-only shell script and atomically
// updates the current effective user's crontab. The command itself never goes
// in the crontab line, avoiding cron's special percent handling and preserving
// arbitrary shell syntax in the requested command.
func scheduledInstallScript(command string, interval time.Duration) (string, error) {
	expression, err := cronExpression(interval)
	if err != nil {
		return "", err
	}
	id := scheduledCommandID(command)
	scriptBody := "#!/bin/sh\n" + envPrefix() + command + "\n"
	marker := "# coordinate:" + id
	return "set -eu; command -v crontab >/dev/null 2>&1 || { echo 'crontab is not available' >&2; exit 127; }; " +
		"umask 077; d=${HOME:?}/.coordinate; mkdir -p \"$d\"; chmod 700 \"$d\"; " +
		"p=\"$d/" + id + ".sh\"; w=\"$p.$$\"; printf '%s\\n' " + shQuote(scriptBody) + " > \"$w\"; chmod 700 \"$w\"; mv -f \"$w\" \"$p\"; " +
		"old=\"$d/.crontab." + id + ".$$\"; next=\"$old.next\"; trap 'rm -f \"$old\" \"$next\"' 0 HUP INT TERM; " +
		"if crontab -l > \"$old\" 2>/dev/null; then sed '/" + marker + "$/d' \"$old\" > \"$next\"; else : > \"$next\"; fi; " +
		"printf '%s\\n' " + shQuote(expression+" /bin/sh \"$HOME/.coordinate/"+id+".sh\" >/dev/null 2>&1 "+marker) + " >> \"$next\"; crontab \"$next\"", nil
}

// systemdInstallScript creates a system-level timer. It is intentionally only
// used with root privileges: user timers frequently depend on a login manager
// and lingering configuration, neither of which is reliable over SSH.
func systemdInstallScript(command string, interval time.Duration) string {
	id := scheduledCommandID(command)
	scriptBody := "#!/bin/sh\n" + envPrefix() + command + "\n"
	service := "[Unit]\nDescription=Coordinate managed recurring command " + id + "\n\n[Service]\nType=oneshot\nExecStart=/bin/sh /etc/coordinate/" + id + ".sh\nTimeoutStartSec=infinity\n"
	timer := "[Unit]\nDescription=Coordinate timer " + id + "\n\n[Timer]\nOnBootSec=15s\nOnUnitActiveSec=" + fmt.Sprintf("%ds", int64(interval/time.Second)) + "\nUnit=coordinate-" + id + ".service\n\n[Install]\nWantedBy=timers.target\n"
	return "set -eu; command -v systemctl >/dev/null 2>&1 || { echo 'systemctl is not available' >&2; exit 127; }; " +
		"systemctl show --property=Version --value >/dev/null 2>&1 || { echo 'systemd is not running' >&2; exit 127; }; " +
		"umask 077; d=/etc/coordinate; mkdir -p \"$d\"; chmod 700 \"$d\"; p=\"$d/" + id + ".sh\"; w=\"$p.$$\"; " +
		"printf '%s\\n' " + shQuote(scriptBody) + " > \"$w\"; chmod 700 \"$w\"; mv -f \"$w\" \"$p\"; " +
		"s=/etc/systemd/system/coordinate-" + id + ".service; sw=\"$s.$$\"; printf '%s\\n' " + shQuote(service) + " > \"$sw\"; chmod 644 \"$sw\"; mv -f \"$sw\" \"$s\"; " +
		"t=/etc/systemd/system/coordinate-" + id + ".timer; tw=\"$t.$$\"; printf '%s\\n' " + shQuote(timer) + " > \"$tw\"; chmod 644 \"$tw\"; mv -f \"$tw\" \"$t\"; " +
		"systemctl daemon-reload; systemctl enable coordinate-" + id + ".timer; systemctl restart coordinate-" + id + ".timer"
}

func systemdUsable(i Instance, client *goph.Client, useSudo bool) bool {
	probe := "command -v systemctl >/dev/null 2>&1 && systemctl show --property=Version --value >/dev/null 2>&1 && printf ready"
	var (
		out []byte
		err error
	)
	if useSudo {
		marker := newSudoInputBoundary(i.Password)
		ctx, cancel := context.WithTimeout(context.Background(), probeCommandTimeout)
		defer cancel()
		out, err = runWithInput(client, ctx, sudoBoundaryCommand(probe, marker), sudoBoundaryInput(i.Password, marker, ""))
	} else {
		out, err = boundedCommand(client, probeCommandTimeout, shWrap(probe))
	}
	return err == nil && strings.TrimSpace(string(out)) == "ready"
}

func selectScheduler(i Instance, client *goph.Client, useSudo bool) (schedulerBackend, error) {
	requested := schedulerBackend(ScheduleBackend)
	rootCapable := i.Username == "root" || useSudo
	checkCron := func() (schedulerBackend, error) {
		if _, err := cronExpression(ScheduleEvery); err != nil {
			return "", fmt.Errorf("cron scheduler cannot represent interval %s portably; use --scheduler=systemd or choose a compatible interval: %w", ScheduleEvery, err)
		}
		return schedulerCron, nil
	}
	switch requested {
	case schedulerSystemd:
		if !rootCapable {
			return "", errors.New("--scheduler=systemd requires root login or --sudo")
		}
		if !systemdUsable(i, client, useSudo) {
			return "", errors.New("--scheduler=systemd requested but a usable systemd manager was not found")
		}
		return schedulerSystemd, nil
	case schedulerCron:
		return checkCron()
	case schedulerAuto:
		if rootCapable && systemdUsable(i, client, useSudo) {
			return schedulerSystemd, nil
		}
		return checkCron()
	default:
		return "", fmt.Errorf("unknown scheduler backend %q", ScheduleBackend)
	}
}

func installScheduledCommand(i Instance, client *goph.Client, command string, interval time.Duration, useSudo bool, backend schedulerBackend) error {
	var (
		installer string
		err       error
	)
	switch backend {
	case schedulerSystemd:
		installer = systemdInstallScript(command, interval)
	case schedulerCron:
		installer, err = scheduledInstallScript(command, interval)
	default:
		return fmt.Errorf("unsupported scheduler backend %q", backend)
	}
	if err != nil {
		return err
	}
	release := acquirePayloadSlot()
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), payloadTimeout())
	defer cancel()

	var output []byte
	if useSudo {
		marker := newSudoInputBoundary(i.Password)
		// -H makes cron jobs land beneath root's home and keeps both backends
		// rooted in the intended system-owned location.
		command := "sudo -H -S -p '' " + shWrap(discardThroughBoundary(marker)+installer)
		output, err = runWithInput(client, ctx, command, sudoBoundaryInput(i.Password, marker, ""))
	} else {
		output, err = runCommand(client, ctx, shWrap(installer))
	}
	if err != nil {
		if isTimeout(err) {
			logger.ErrExtra(i, fmt.Sprintf("scheduled command installation timed out on %s", hostLabel(i)))
		} else if errors.Is(err, errRemoteOutputLimit) {
			logger.ErrExtra(i, fmt.Sprintf("scheduled command installation output exceeded the %d-byte capture limit on %s", maxCapturedRemoteOutput, hostLabel(i)))
		} else {
			logger.ErrExtra(i, fmt.Sprintf("scheduled command installation failed on %s: %s", hostLabel(i), err))
		}
	}
	if len(output) > 0 {
		logger.DebugExtra(i, "scheduled command installer returned output")
	}
	return err
}
