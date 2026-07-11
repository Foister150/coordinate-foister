package ssh

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
	cryptossh "golang.org/x/crypto/ssh"
)

const (
	defaultTransferTimeout = 15 * time.Minute
	// Per-host -l remains the local scheduling control. This second process-wide
	// ceiling prevents max-hosts*limit simultaneous SSH streams, local tar walks,
	// and rsync processes from exhausting descriptors, memory, or disk I/O.
	maxExpensiveOperations = 64
)

type operationLimiter struct {
	slots chan struct{}
}

func newOperationLimiter(limit int) *operationLimiter {
	return &operationLimiter{slots: make(chan struct{}, limit)}
}

func (l *operationLimiter) acquire(ctx context.Context) (func(), error) {
	select {
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var expensiveOperations = newOperationLimiter(maxExpensiveOperations)

func transferTimeout() time.Duration {
	if TransferTimeout > 0 {
		return TransferTimeout
	}
	return defaultTransferTimeout
}

func runTransferOperation(label string, operation func(context.Context) error) error {
	timeout := transferTimeout()
	// Queueing does not consume the operator's transfer budget. Every active
	// operation is bounded, so a slot is guaranteed to be released without
	// spuriously failing work merely because more than 64 hosts were scheduled.
	release, _ := expensiveOperations.acquire(context.Background())
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := operation(ctx)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %s; partial transfer content may remain: %w", label, timeout, errors.Join(err, ctx.Err()))
	}
	return err
}

// closeOnContext interrupts blocking SSH/SFTP I/O on cancellation and waits
// for the watcher to exit before its caller releases the underlying object.
func closeOnContext(ctx context.Context, closeFn func() error) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = closeFn()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func newSessionContext(ctx context.Context, client *goph.Client) (*cryptossh.Session, error) {
	type result struct {
		session *cryptossh.Session
		err     error
	}
	ready := make(chan result, 1)
	go func() {
		session, err := client.NewSession()
		if ctx.Err() != nil && session != nil {
			_ = session.Close()
		}
		ready <- result{session: session, err: err}
	}()
	select {
	case opened := <-ready:
		return opened.session, opened.err
	case <-ctx.Done():
		// x/crypto/ssh offers no context-aware channel open. Closing the stalled
		// transport is the only reliable way to unblock it; sibling operations on
		// an unresponsive connection will fail rather than hang indefinitely.
		_ = client.Close()
		return nil, ctx.Err()
	}
}

func newSFTPContext(ctx context.Context, client *goph.Client) (*sftp.Client, error) {
	type result struct {
		client *sftp.Client
		err    error
	}
	ready := make(chan result, 1)
	go func() {
		ftp, err := client.NewSftp()
		if ctx.Err() != nil && ftp != nil {
			_ = ftp.Close()
		}
		ready <- result{client: ftp, err: err}
	}()
	select {
	case opened := <-ready:
		return opened.client, opened.err
	case <-ctx.Done():
		_ = client.Close()
		return nil, ctx.Err()
	}
}

func acquirePayloadSlot() func() {
	release, _ := expensiveOperations.acquire(context.Background())
	return release
}
