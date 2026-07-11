package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestOperationLimiterQueuesBeyondLimit(t *testing.T) {
	limiter := newOperationLimiter(2)
	gate := make(chan struct{})
	started := make(chan struct{}, 7)
	var active atomic.Int32
	var peak atomic.Int32
	var wg sync.WaitGroup
	for range 7 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := limiter.acquire(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			current := active.Add(1)
			for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
			}
			started <- struct{}{}
			<-gate
			active.Add(-1)
			release()
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for initial operation slots")
		}
	}
	select {
	case <-started:
		t.Fatal("more operations started than the limiter permits")
	case <-time.After(25 * time.Millisecond):
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak active operations = %d, want 2", got)
	}
	close(gate)
	wg.Wait()
}

func TestRunTransferOperationReportsTimeoutAndPartialState(t *testing.T) {
	original := TransferTimeout
	TransferTimeout = 30 * time.Millisecond
	defer func() { TransferTimeout = original }()

	err := runTransferOperation("test transfer", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "partial transfer content may remain") {
		t.Fatalf("error = %v, want explicit partial-transfer warning", err)
	}
}

func TestRunRsyncContextCancelsProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake rsync uses a POSIX script")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rsync")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runRsyncContext(ctx, Instance{Username: "admin", IP: "127.0.0.1"}, "/source", "admin@host:/dest")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("cancelled rsync took %v to return", time.Since(start))
	}
}

func TestRsyncOutputIsBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake rsync uses a POSIX script")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rsync")
	script := "#!/bin/sh\nhead -c 1100000 /dev/zero\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	err := runRsync(Instance{Username: "admin", IP: "127.0.0.1"}, "/source", "admin@host:/dest")
	if err == nil {
		t.Fatal("noisy failed rsync unexpectedly succeeded")
	}
	if len(err.Error()) > 4096 {
		t.Fatalf("rsync error grew unexpectedly large: %d bytes", len(err.Error()))
	}
}
