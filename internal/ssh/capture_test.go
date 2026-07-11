package ssh

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestBoundedCaptureLimitsMemoryAndReportsTruncation(t *testing.T) {
	capture := &boundedCapture{}
	payload := bytes.Repeat([]byte("x"), maxCapturedRemoteOutput+123)
	n, err := capture.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	got := capture.Bytes()
	if len(got) > maxCapturedRemoteOutput+128 {
		t.Fatalf("captured length = %d, expected bounded payload plus marker", len(got))
	}
	if !strings.Contains(string(got), "123 bytes omitted") {
		t.Fatalf("missing truncation marker: %q", got[len(got)-100:])
	}
	if err := capture.Err(); err == nil || !strings.Contains(err.Error(), "truncated output retained") {
		t.Fatalf("Err() = %v, want explicit truncation failure", err)
	}
}

func TestBoundedCaptureConcurrentWriters(t *testing.T) {
	capture := &boundedCapture{}
	const writers = 32
	chunk := bytes.Repeat([]byte("y"), 64*1024)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := capture.Write(chunk); err != nil || n != len(chunk) {
				t.Errorf("Write() = (%d, %v)", n, err)
			}
		}()
	}
	wg.Wait()
	got := capture.Bytes()
	if !strings.Contains(string(got), "remote output truncated") {
		t.Fatal("concurrent overflow did not report truncation")
	}
}
