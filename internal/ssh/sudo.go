package ssh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/melbahja/goph"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

// sudoProbeTimeout bounds the up-front sudo check. It is generous enough to
// tolerate a slow PAM stack (and sudo's deliberate delay after a bad password)
// without inheriting the potentially long per-command --timeout.
const sudoProbeTimeout = 15 * time.Second

// sudoDecision distinguishes the normal unprivileged path from an explicitly
// requested escalation that failed. Collapsing both states into false caused
// root-intended payloads to run silently as the SSH user.
type sudoDecision uint8

const (
	sudoNotNeeded sudoDecision = iota
	sudoAvailable
	sudoFailed
)

// decideSudo contains the policy separately from the SSH probe so it can be
// exhaustively unit tested. A root login never needs a sudo wrapper.
func decideSudo(username string, requested, escalationSucceeded bool) sudoDecision {
	if username == "root" || !requested {
		return sudoNotNeeded
	}
	if escalationSucceeded {
		return sudoAvailable
	}
	return sudoFailed
}

// escalateSudo verifies that the authenticated password lets this user run
// commands as root via sudo. Each SSH command runs in its own session, so a
// persistent `sudo -s`/`sudo su` shell (as the old code attempted) would not
// carry over to later commands — instead every root payload is individually
// prefixed with `sudo -S` and fed the password on stdin. This function just
// confirms up front that that will work, so the caller knows whether to bother.
//
// The password is delivered over the SSH channel's stdin, never echoed on the
// command line, keeping it out of the remote process table and shell history.
func escalateSudo(i Instance, client *goph.Client) bool {
	logger.Info(fmt.Sprintf("%s: Verifying sudo escalation.", i.IP))

	ctx, cancel := context.WithTimeout(context.Background(), sudoProbeTimeout)
	defer cancel()

	// `id -u` is portable across Linux and the BSDs; root is uid 0.
	out, err := runWithInput(client, ctx, "sudo -S -p '' id -u", i.Password+"\n")
	if err == nil && isRootID(out) {
		logger.Info(i, "Successfully escalated privileges with sudo.")
		return true
	}

	logger.Err(i, "Failed to escalate privileges with sudo.")
	return false
}

// isRootID reports whether any line of `id -u` output is uid 0. sudo -S may emit
// a prompt or warning on stderr (captured in the same buffer), so we scan lines
// rather than trimming the whole blob.
func isRootID(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "0" {
			return true
		}
	}
	return false
}
