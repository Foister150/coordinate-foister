package runner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melbahja/goph"
	flag "github.com/spf13/pflag"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	. "github.com/LanodonF/coordinate-foister/internal/config"
	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/ssh"
)

const defaultSSHConnectTimeout = 10 * time.Second

// sshConnectTimeout keeps both the TCP connection and SSH handshake bounded.
// Respect a shorter user timeout, but do not let the per-payload timeout make
// connection establishment needlessly slow by default.
func sshConnectTimeout() time.Duration {
	if Timeout > 0 && Timeout < defaultSSHConnectTimeout {
		return Timeout
	}
	return defaultSSHConnectTimeout
}

// newGophConnection is equivalent to goph.NewConn, but keeps one absolute
// deadline across both TCP establishment and the SSH protocol handshake.
// goph.Config.Timeout is otherwise passed only to ssh.Dial's TCP dial; a peer
// that accepts TCP and never sends an SSH identification string can hang
// forever in ssh.NewClientConn.
func newGophConnection(config *goph.Config) (*goph.Client, error) {
	address := net.JoinHostPort(config.Addr, fmt.Sprint(config.Port))
	dialer := net.Dialer{}
	var deadline time.Time
	if config.Timeout > 0 {
		deadline = time.Now().Add(config.Timeout)
		dialer.Deadline = deadline
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set SSH handshake deadline: %w", err)
		}
	}

	sshConn, channels, requests, err := cryptossh.NewClientConn(conn, address, &cryptossh.ClientConfig{
		User:            config.User,
		Auth:            config.Auth,
		Timeout:         config.Timeout,
		HostKeyCallback: config.Callback,
		BannerCallback:  config.BannerCallback,
	})
	if err != nil {
		return nil, err
	}

	// Session operations have their own bounded runners. Do not leave the
	// connection-establishment deadline active after authentication succeeds.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = sshConn.Close()
		return nil, fmt.Errorf("clear SSH handshake deadline: %w", err)
	}

	closeOnError = false
	return &goph.Client{
		Client: cryptossh.NewClient(sshConn, channels, requests),
		Config: config,
	}, nil
}

var dialGophConnection = newGophConnection

var hostJobCounter atomic.Uint64

func KeyAuthEnabled() bool {
	return keyAuthEnabled(flag.CommandLine)
}

func keyAuthEnabled(flags *flag.FlagSet) bool {
	return flags.Changed("key")
}

func keyAuth() (goph.Auth, string, func(), error) {
	keyPath := strings.TrimSpace(*Key)
	if keyPath == "" || keyPath == AgentKeyFlagValue {
		sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, "ssh-agent", nil, fmt.Errorf("could not find ssh agent: %w", err)
		}

		cleanup := func() {
			_ = sshAgent.Close()
		}
		return goph.Auth{cryptossh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)}, "ssh-agent", cleanup, nil
	}

	auth, err := goph.Key(keyPath, "")
	return auth, keyPath, nil, err
}

func handleSSHConnection(i Instance, client *goph.Client) HostWorkResult {
	logger.InfoExtra(i, fmt.Sprintf("Valid credentials for username '%s'", i.Username))
	if *ConfigOnly != "" {
		UpdateEntry(ConfigEntry{IP: i.IP, Username: i.Username, Password: *ConfigOnly})
	}
	result := ssh.SsherWrapper(i, client)
	if err := client.Close(); err != nil {
		logger.ErrExtra(i, fmt.Sprintf("failed to close SSH connection: %s", err))
		result.Failures = append(result.Failures, fmt.Errorf("close SSH connection: %w", err))
	}
	return result
}

func attemptSSH(ip, outfile, username, password string, outputOwner uint64) (bool, HostWorkResult, error) {
	logger.Debug(fmt.Sprintf("Starting password authentication for IP %s with username %s", ip, username))

	i := Instance{
		IP:          ip,
		Outfile:     outfile,
		Username:    username,
		Password:    password,
		OutputOwner: outputOwner,
	}

	// KeyboardInteractive includes both password and keyboard-interactive auth
	// methods. Offering them in one handshake avoids a second TCP connection for
	// every rejected credential on servers that disable password auth but accept
	// keyboard-interactive.
	client, err := dialGophConnection(&goph.Config{
		User:     i.Username,
		Addr:     i.IP,
		Port:     uint(*Port), // #nosec G115 -- CLI validation enforces 1..65535.
		Auth:     goph.KeyboardInteractive(i.Password),
		Timeout:  sshConnectTimeout(),
		Callback: cryptossh.InsecureIgnoreHostKey(), // #nosec G106 -- documented lab policy; CF-031 tracks configurable verification.
	})
	if err != nil {
		return false, HostWorkResult{}, err
	}
	return true, handleSSHConnection(i, client), nil
}

func expectedAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") ||
		strings.Contains(msg, "permission denied") ||
		// Servers with a very small MaxAuthTries commonly disconnect after a
		// single rejected method. Each candidate gets a fresh SSH connection, so
		// this is still a credential-level rejection rather than a reason to
		// abandon the remaining password/key matrix for the host.
		strings.Contains(msg, "too many authentication failures")
}

func requestedHostWork() HostWorkResult {
	payloads := len(Scripts)
	if len(Commands) > 0 {
		payloads = len(Commands)
	}
	if len(ScheduledCommands) > 0 {
		payloads = len(ScheduledCommands)
	}
	transfers := 0
	if len(*UploadFiles) > 0 {
		transfers++
	}
	if len(*DownloadDirs) > 0 {
		transfers++
	}
	return HostWorkResult{PayloadsRequested: payloads, TransfersRequested: transfers}
}

func RunnerBf(ip string, outfile string, w *sync.WaitGroup) {
	defer w.Done()
	logger.Debug(fmt.Sprintf("Starting RunnerBf for IP: %s", ip))

	i := Instance{IP: ip, Outfile: outfile, OutputOwner: hostJobCounter.Add(1)}

	keyAuthRequested := KeyAuthEnabled()
	var (
		keyAuthMethod  goph.Auth
		keyAuthSource  string
		keyAuthCleanup func()
		keyAuthErr     error
		keyAuthLoaded  bool
	)

	found := false
	attempts := 0
	var lastErr error
	var work HostWorkResult
	winningUsername := ""
	stop := false
	for _, u := range UsernameList {
		if found || stop {
			logger.Debug(fmt.Sprintf("Skipping remaining usernames for %s after terminal connection result.", ip))
			break
		}
		i.Username = u
		for _, p := range PasswordList {
			if p == "" {
				logger.Debug(fmt.Sprintf("Skipping empty password for user '%s'", u))
				continue
			}
			logger.DebugExtra(i, fmt.Sprintf("Trying password authentication for username '%s'", u))
			attempts++
			ok, attemptWork, err := attemptSSH(ip, outfile, u, p, i.OutputOwner)
			if ok {
				found = true
				work = attemptWork
				winningUsername = u
				break
			}
			lastErr = err
			logger.DebugExtra(i, fmt.Sprintf("Authentication attempt for username '%s' failed: %s", u, err))
			// A refused connection, protocol mismatch, or handshake timeout is a
			// host-level failure. Retrying the whole credential matrix cannot fix it.
			if !expectedAuthFailure(err) {
				stop = true
				break
			}
		}

		if !found && !stop && keyAuthRequested {
			i.Username = u
			if !keyAuthLoaded {
				keyAuthMethod, keyAuthSource, keyAuthCleanup, keyAuthErr = keyAuth()
				keyAuthLoaded = true
				if keyAuthErr != nil {
					lastErr = fmt.Errorf("error loading key authentication from %s: %w", keyAuthSource, keyAuthErr)
					logger.DebugExtra(i, lastErr)
					keyAuthRequested = false
					continue
				}
				if keyAuthCleanup != nil {
					defer keyAuthCleanup()
				}
			}
			logger.DebugExtra(i, fmt.Sprintf("Trying key-based authentication from %s for username '%s'", keyAuthSource, u))
			attempts++
			client, err := dialGophConnection(&goph.Config{
				User:     u,
				Addr:     ip,
				Port:     uint(*Port), // #nosec G115 -- CLI validation enforces 1..65535.
				Auth:     keyAuthMethod,
				Timeout:  sshConnectTimeout(),
				Callback: cryptossh.InsecureIgnoreHostKey(), // #nosec G106 -- documented lab policy; CF-031 tracks configurable verification.
			})
			if err == nil {
				work = handleSSHConnection(i, client)
				found = true
				winningUsername = u
			} else {
				lastErr = err
				logger.DebugExtra(i, fmt.Sprintf("Key authentication for username '%s' failed: %s", u, err))
				if !expectedAuthFailure(err) {
					stop = true
				}
			}
		}
	}

	if !found {
		msg := fmt.Sprintf("Unable to connect to %s after %d authentication attempt(s)", ip, attempts)
		if lastErr != nil {
			msg += ": " + lastErr.Error()
		}
		logger.ErrExtra(i, msg)
		RecordHostResult(HostResult{Host: ip, Username: i.Username, AuthAttempts: attempts, AuthErr: errors.New(msg), Work: requestedHostWork()})
		return
	}
	RecordHostResult(HostResult{Host: ip, Username: winningUsername, AuthAttempts: attempts, Authenticated: true, Work: work})
}

func RunnerCred(ip string, outfile string, w *sync.WaitGroup, username, password string) {
	defer w.Done()
	logger.Debug(fmt.Sprintf("Starting RunnerCred for IP: %s, username: %s", ip, username))

	outputOwner := hostJobCounter.Add(1)
	ok, work, err := attemptSSH(ip, outfile, username, password, outputOwner)
	if !ok {
		i := Instance{IP: ip, Outfile: outfile, Username: username}
		msg := fmt.Sprintf("Login attempt failed for %s as %s: %s", ip, username, err)
		logger.ErrExtra(i, msg)
		RecordHostResult(HostResult{Host: ip, Username: username, AuthAttempts: 1, AuthErr: errors.New(msg), Work: requestedHostWork()})
	} else {
		logger.Debug(fmt.Sprintf("Login succeeded for IP: %s, username: %s", ip, username))
		RecordHostResult(HostResult{Host: ip, Username: username, AuthAttempts: 1, Authenticated: true, Work: work})
	}
}
