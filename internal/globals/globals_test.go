package globals

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDefaultTmpDirUsesOSTemp(t *testing.T) {
	want := filepath.Join(os.TempDir(), "coordinate")
	if DefaultTmpDir != want {
		t.Fatalf("DefaultTmpDir = %q, want %q", DefaultTmpDir, want)
	}
}

func TestConcurrentHostResultsAreRaceSafeAndReconciled(t *testing.T) {
	ResetHostResults()
	t.Cleanup(ResetHostResults)

	const n = 300
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RecordHostResult(HostResult{
				Host:          "host",
				AuthAttempts:  2,
				Authenticated: true,
				Work: HostWorkResult{
					PayloadsRequested: 1,
					Payloads:          []OperationResult{{Kind: "command"}},
				},
			})
		}()
	}
	wg.Wait()

	summary := SummarizeHostResults()
	if summary.HostsAttempted != n || summary.HostsSucceeded != n || summary.AuthenticationTries != 2*n {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.PayloadsRequested != n || summary.PayloadsAttempted != n || summary.PayloadsSucceeded != n {
		t.Fatalf("payload summary = %+v", summary)
	}
}

func TestRunSummaryCountsFailuresTimeoutsAndSkippedWork(t *testing.T) {
	ResetHostResults()
	t.Cleanup(ResetHostResults)
	RecordHostResult(HostResult{
		Host:          "failed",
		Authenticated: true,
		AuthAttempts:  3,
		Work: HostWorkResult{
			PayloadsRequested:  3,
			TransfersRequested: 2,
			Payloads: []OperationResult{
				{Kind: "command", Err: context.DeadlineExceeded},
				{Kind: "command", Err: errors.New("exit 1")},
			},
			Transfers: []OperationResult{{Kind: "upload"}},
		},
	})
	summary := SummarizeHostResults()
	if summary.HostsFailed != 1 || summary.PayloadsFailed != 2 || summary.PayloadsTimedOut != 1 || summary.PayloadsSkipped != 1 || summary.TransfersSucceeded != 1 || summary.TransfersSkipped != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.PayloadsRequested != summary.PayloadsSucceeded+summary.PayloadsFailed+summary.PayloadsSkipped {
		t.Fatalf("payload metrics do not reconcile: %+v", summary)
	}
}

func TestSelectOutputModePrecedence(t *testing.T) {
	tests := []struct {
		name                                 string
		errorsOnly, superQuiet, debug, quiet bool
		want                                 OutputMode
	}{
		{name: "normal", want: OutputNormal},
		{name: "quiet", quiet: true, want: OutputQuiet},
		{name: "debug over quiet", debug: true, quiet: true, want: OutputDebug},
		{name: "super quiet over debug", superQuiet: true, debug: true, quiet: true, want: OutputSuperQuiet},
		{name: "errors over every mode", errorsOnly: true, superQuiet: true, debug: true, quiet: true, want: OutputErrorsOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectOutputMode(tt.errorsOnly, tt.superQuiet, tt.debug, tt.quiet); got != tt.want {
				t.Fatalf("SelectOutputMode() = %v, want %v", got, tt.want)
			}
		})
	}
}
