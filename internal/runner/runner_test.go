package runner

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/melbahja/goph"
	flag "github.com/spf13/pflag"
	cryptossh "golang.org/x/crypto/ssh"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestNewGophConnectionBoundsSilentSSHHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan struct{})
	serverExited := make(chan struct{})
	defer func() {
		close(serverDone)
		_ = listener.Close()
		<-serverExited
	}()
	go func() {
		defer close(serverExited)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept TCP but deliberately never send the SSH identification line.
		<-serverDone
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	const timeout = 150 * time.Millisecond
	start := time.Now()
	client, err := newGophConnection(&goph.Config{
		User:     "test",
		Addr:     host,
		Port:     uint(port),
		Timeout:  timeout,
		Callback: cryptossh.InsecureIgnoreHostKey(),
	})
	elapsed := time.Since(start)
	if client != nil {
		client.Close()
		t.Fatal("silent server unexpectedly completed an SSH handshake")
	}
	if err == nil {
		t.Fatal("silent server unexpectedly returned no error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("silent SSH handshake error = %v, want a network timeout", err)
	}
	if elapsed < timeout/2 {
		t.Fatalf("silent SSH handshake returned too early after %v, want deadline near %v", elapsed, timeout)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("silent SSH handshake returned after %v, want a bounded return near %v", elapsed, timeout)
	}
}

func TestSSHConnectTimeout(t *testing.T) {
	original := Timeout
	defer func() { Timeout = original }()

	Timeout = 0
	if got := sshConnectTimeout(); got != defaultSSHConnectTimeout {
		t.Fatalf("zero timeout produced %v, want %v", got, defaultSSHConnectTimeout)
	}
	Timeout = 2 * time.Second
	if got := sshConnectTimeout(); got != 2*time.Second {
		t.Fatalf("short timeout produced %v, want 2s", got)
	}
	Timeout = time.Minute
	if got := sshConnectTimeout(); got != defaultSSHConnectTimeout {
		t.Fatalf("long timeout produced %v, want %v", got, defaultSSHConnectTimeout)
	}
}

func TestExpectedAuthFailure(t *testing.T) {
	for _, message := range []string{
		"ssh: unable to authenticate, attempted methods [none password]",
		"ssh: handshake failed: ssh: disconnect, reason 2: Too many authentication failures",
	} {
		if !expectedAuthFailure(errors.New(message)) {
			t.Fatalf("authentication rejection %q was not classified as expected", message)
		}
	}
	if expectedAuthFailure(errors.New("ssh: handshake failed: read tcp: i/o timeout")) {
		t.Fatal("transport timeout was classified as an authentication rejection")
	}
}

func TestKeyAuthEnabledRequiresKeyFlag(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/coordinate-test-agent.sock")

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.StringP("key", "k", "", "")
	flags.Lookup("key").NoOptDefVal = AgentKeyFlagValue

	if err := flags.Parse([]string{}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if keyAuthEnabled(flags) {
		t.Fatal("keyAuthEnabled() = true without -k; want false")
	}
}

func TestKeyAuthEnabledWithOptionalKeyFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "agent key", args: []string{"-k"}},
		{name: "explicit short key path", args: []string{"-k=/tmp/id_ed25519"}},
		{name: "explicit long key path", args: []string{"--key=/tmp/id_ed25519"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			flags.StringP("key", "k", "", "")
			flags.Lookup("key").NoOptDefVal = AgentKeyFlagValue

			if err := flags.Parse(tt.args); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if !keyAuthEnabled(flags) {
				t.Fatal("keyAuthEnabled() = false with -k; want true")
			}
		})
	}
}

func TestRunnerBfRecordsOneFailureAfterExpectedAuthMatrix(t *testing.T) {
	originalDial := dialGophConnection
	originalUsers := UsernameList
	originalPasswords := PasswordList
	dialGophConnection = func(*goph.Config) (*goph.Client, error) {
		return nil, errors.New("ssh: unable to authenticate, attempted methods [none password]")
	}
	UsernameList = []string{"root", "admin"}
	PasswordList = []string{"one", "two"}
	ResetHostResults()
	t.Cleanup(func() {
		dialGophConnection = originalDial
		UsernameList = originalUsers
		PasswordList = originalPasswords
		ResetHostResults()
	})

	var wg sync.WaitGroup
	wg.Add(1)
	RunnerBf("192.0.2.90", "", &wg)
	wg.Wait()
	results := HostResultsSnapshot()
	if len(results) != 1 {
		t.Fatalf("host results = %d, want 1", len(results))
	}
	if results[0].Authenticated || results[0].AuthAttempts != 4 || results[0].Successful() {
		t.Fatalf("host result = %+v", results[0])
	}
}

func TestRequestedHostWorkCountsSkippedWorkAfterAuthFailure(t *testing.T) {
	originalCommands := Commands
	originalScripts := Scripts
	originalUploads := append([]string(nil), (*UploadFiles)...)
	originalDownloads := append([]string(nil), (*DownloadDirs)...)
	Commands = []string{"one", "two"}
	Scripts = []string{"ignored-when-commands-present"}
	*UploadFiles = []string{"local;/remote"}
	*DownloadDirs = []string{"/remote"}
	t.Cleanup(func() {
		Commands = originalCommands
		Scripts = originalScripts
		*UploadFiles = originalUploads
		*DownloadDirs = originalDownloads
	})

	work := requestedHostWork()
	if work.PayloadsRequested != 2 || work.TransfersRequested != 2 {
		t.Fatalf("requested work = %+v, want 2 payloads and 2 transfer phases", work)
	}
}
