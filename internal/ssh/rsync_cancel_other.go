//go:build !unix

package ssh

import "os/exec"

// Non-Unix platforms retain exec.CommandContext's safe direct-process kill.
// Native Windows password mode is disabled because its POSIX askpass helper is
// unavailable; key-mode rsync remains bounded by WaitDelay.
func configureRsyncCancellation(_ *exec.Cmd) {}
