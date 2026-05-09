package runner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/melbahja/goph"
	flag "github.com/spf13/pflag"
	cryptossh "golang.org/x/crypto/ssh"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/ssh"
)

func KeyAuthEnabled() bool {
	if flag.CommandLine.Changed("key") {
		return true
	}
	return *Passwords == "" && *CreateConfig == "" && goph.HasAgent()
}

func keyAuth() (goph.Auth, string, error) {
	keyPath := strings.TrimSpace(*Key)
	if keyPath == "" || keyPath == AgentKeyFlagValue {
		auth, err := goph.UseAgent()
		return auth, "ssh-agent", err
	}

	auth, err := goph.Key(keyPath, "")
	return auth, keyPath, err
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

		if !found && KeyAuthEnabled() {
			i.Username = u
			privKey, source, err := keyAuth()
			if err != nil {
				logger.ErrExtra(i, fmt.Sprintf("Error loading key authentication from %s for user '%s': %s", source, u, err))
				continue
			}
			logger.DebugExtra(i, fmt.Sprintf("Trying key-based authentication from %s for username '%s'", source, u))
			client, err := goph.NewConn(&goph.Config{
				User:     u,
				Addr:     ip,
				Port:     uint(*Port),
				Auth:     privKey,
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
