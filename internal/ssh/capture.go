package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

// maxCapturedRemoteOutput bounds merged stdout/stderr held in memory for one
// SSH command. Writers still report the full write as consumed so a noisy
// remote process cannot block forever once the diagnostic buffer is full.
const maxCapturedRemoteOutput = 1 << 20 // 1 MiB per active session

var errRemoteOutputLimit = errors.New("remote output exceeded the in-memory capture limit")

type boundedCapture struct {
	mu      sync.Mutex
	b       bytes.Buffer
	omitted int64
}

func (w *boundedCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	originalLen := len(p)
	remaining := maxCapturedRemoteOutput - w.b.Len()
	written := 0
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.b.Write(p)
		written = len(p)
	}
	w.omitted += int64(originalLen - written)
	return originalLen, nil
}

func (w *boundedCapture) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	result := append([]byte(nil), w.b.Bytes()...)
	if w.omitted > 0 {
		result = append(result, []byte(fmt.Sprintf("\n[coordinate: remote output truncated; %d bytes omitted]\n", w.omitted))...)
	}
	return result
}

func (w *boundedCapture) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.omitted == 0 {
		return nil
	}
	return fmt.Errorf("%w (%d bytes omitted; truncated output retained)", errRemoteOutputLimit, w.omitted)
}
