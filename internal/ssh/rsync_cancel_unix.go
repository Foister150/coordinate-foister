//go:build unix

package ssh

import (
	"os/exec"
	"syscall"
)

// configureRsyncCancellation isolates rsync and its ssh child in a process
// group so a transfer deadline terminates the complete local transport tree.
func configureRsyncCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
