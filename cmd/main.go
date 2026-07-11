package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"

	"github.com/LanodonF/coordinate-foister/internal/cli"
	"github.com/LanodonF/coordinate-foister/internal/config"
	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
	"github.com/LanodonF/coordinate-foister/internal/runner"
	"github.com/LanodonF/coordinate-foister/internal/utils"
)

func main() {
	os.Exit(run())
}

func run() int {
	ResetHostResults()
	logger.Debug("Starting the application...")

	if err := cli.Init(); err != nil {
		if errors.Is(err, cli.ErrHelp) {
			return 0
		}
		cli.PrintUsageError(os.Stderr, err)
		return 2
	}
	logger.Debug("CLI initialization completed.")
	err := cli.InputCheck()
	if err != nil {
		cli.PrintUsageError(os.Stderr, err)
		return 2
	}
	if err := parseRequestedTargets(); err != nil {
		cli.PrintUsageError(os.Stderr, err)
		return 2
	}

	logger.Debug(fmt.Sprintf("UseConfig flag: %v", *UseConfig))
	if *UseConfig {
		if err := useConfigDeploy(); err != nil {
			logger.Err(fmt.Sprintf("Configuration deployment failed: %v", err))
			return 1
		}
	} else {
		// Both manual configuration modes mutate the credential store. Load the
		// existing file first so successful hosts are merged into it rather than
		// replacing unrelated credentials. A malformed/unreadable file is a hard
		// stop: continuing would risk overwriting the last usable configuration.
		if *CreateConfig != "" || *ConfigOnly != "" {
			if err := config.ReadConfig(); err != nil {
				logger.Err(fmt.Sprintf("Cannot update configuration: %v", err))
				return 1
			}
		}
		if err := prepareManualDeploy(); err != nil {
			logger.Err(err)
			return 1
		}
	}
	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	logger.Debug(fmt.Sprintf("Key authentication requested: %t; password candidates: %d", runner.KeyAuthEnabled(), len(PasswordList)))
	if runner.KeyAuthEnabled() || len(PasswordList) != 0 {
		if err := useManualDeploy(); err != nil {
			logger.Err(err)
			return 1
		}
	}

	var saveErr error
	if *CreateConfig != "" || *ConfigOnly != "" {
		logger.Debug("CreateConfig flag detected. Saving config...")
		if saveErr = config.SaveConfig(); saveErr != nil {
			logger.Err(fmt.Sprintf("Configuration was not saved: %v", saveErr))
		}
	}

	summary := SummarizeHostResults()
	logger.Info(formatRunSummary(summary))
	logger.Debug("Application execution completed.")
	if saveErr != nil || summary.HostsFailed > 0 {
		return 1
	}
	return 0
}

func parseRequestedTargets() error {
	if strings.TrimSpace(*Targets) == "" {
		Addresses = nil
		StringAddresses = nil
		return nil
	}
	addresses, stringsFound, err := utils.ParseIPsWithLimit(*Targets, *MaxTargets)
	if err != nil {
		return fmt.Errorf("invalid --targets value: %w", err)
	}
	Addresses = addresses
	StringAddresses = stringsFound
	return nil
}

func formatRunSummary(summary RunSummary) string {
	return fmt.Sprintf(
		"Run summary: hosts attempted=%d authenticated=%d succeeded=%d failed=%d; authentication attempts=%d; payloads requested=%d attempted=%d succeeded=%d failed=%d skipped=%d timed-out=%d; transfer phases requested=%d attempted=%d succeeded=%d failed=%d skipped=%d\n",
		summary.HostsAttempted, summary.HostsAuthenticated, summary.HostsSucceeded, summary.HostsFailed,
		summary.AuthenticationTries,
		summary.PayloadsRequested, summary.PayloadsAttempted, summary.PayloadsSucceeded, summary.PayloadsFailed, summary.PayloadsSkipped, summary.PayloadsTimedOut,
		summary.TransfersRequested, summary.TransfersAttempted, summary.TransfersSucceeded, summary.TransfersFailed, summary.TransfersSkipped,
	)
}

func useConfigDeploy() error {
	logger.Debug("Starting useConfigDeploy...")
	if err := config.ReadConfig(); err != nil {
		return err
	}

	tempConfigEntries := config.Snapshot()
	if len(tempConfigEntries) == 0 {
		return fmt.Errorf("no entries in config file")
	}

	logger.Debug(fmt.Sprintf("Config entries found: %d", len(tempConfigEntries)))

	if *Targets != "" {
		logger.Debug("Filtering config entries based on specified targets...")
		filteredEntries := []config.ConfigEntry{}
		for _, entry := range tempConfigEntries {
			for _, address := range Addresses {
				if entry.IP == address.String() {
					filteredEntries = append(filteredEntries, entry)
					break
				}
			}
		}
		tempConfigEntries = filteredEntries
		logger.Debug(fmt.Sprintf("Filtered config entries: %d", len(tempConfigEntries)))
		if len(tempConfigEntries) == 0 {
			return fmt.Errorf("no configuration entries match the requested targets")
		}
	}

	var wg sync.WaitGroup
	sem := newHostLimiter()
	for _, Entry := range tempConfigEntries {
		logger.Debug(fmt.Sprintf("Running config entry for host %s with username %s", Entry.IP, Entry.Username))
		wg.Add(1)
		sem.acquire()
		go func(entry config.ConfigEntry) {
			defer sem.release()
			runner.RunnerCred(entry.IP, *Outfile, &wg, entry.Username, entry.Password)
		}(Entry)
	}
	wg.Wait()
	logger.Debug("useConfigDeploy completed.")
	return nil
}

func prepareManualDeploy() error {
	logger.Debug("Starting prepareManualDeploy...")

	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	if ActiveOutputMode == OutputNormal || ActiveOutputMode == OutputDebug {
		var summary strings.Builder
		fmt.Fprintf(&summary, "Specified targets (%d addresses):\n\t%s\n", len(Addresses), strings.Join(StringAddresses, "\n\t"))
		if len(Scripts) > 0 {
			fmt.Fprintf(&summary, "Specified scripts (%d files):\n\t%s\n", len(Scripts), strings.Join(Scripts, "\n\t"))
		}
		if len(Commands) > 0 {
			fmt.Fprintf(&summary, "Specified commands (%d commands; contents omitted).\n", len(Commands))
		}
		if len(EnvironCmds) != 0 {
			fmt.Fprintf(&summary, "Specified environment variables (%d items; values redacted):\n\t%s\n", len(EnvironCmds), strings.Join(environmentKeys(EnvironCmds), "\n\t"))
		}
		logger.Status(summary.String())
	}

	UsernameList = strings.Split(*Usernames, ",")
	logger.Debug(fmt.Sprintf("Parsed usernames: %v", UsernameList))

	if *Passwords == "" && *CreateConfig == "" && !runner.KeyAuthEnabled() {
		fmt.Fprint(os.Stderr, "Password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		PasswordList = []string{strings.TrimSpace(string(password))}
		fmt.Fprintln(os.Stderr)
		logger.Debug("Password read from terminal.")
	} else if *Passwords != "" {
		PasswordList = strings.Split(*Passwords, ",")
		logger.Debug(fmt.Sprintf("Parsed %d password candidates.", len(PasswordList)))
	} else if *Key != "" && *Key != AgentKeyFlagValue {
		if _, err := os.ReadFile(strings.TrimSpace(*Key)); err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		logger.Debug(fmt.Sprintf("Key file found: %s", *Key))
	}
	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	logger.Debug("prepareManualDeploy completed.")
	return nil
}

func environmentKeys(assignments []string) []string {
	keys := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		key, _, _ := strings.Cut(assignment, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			key = "[invalid key]"
		}
		keys = append(keys, key)
	}
	return keys
}

func useManualDeploy() error {
	logger.Debug("Starting useManualDeploy...")

	if len(Addresses) == 0 {
		return errors.New("no addresses to deploy; ensure target IPs are parsed correctly")
	}

	var wg sync.WaitGroup
	sem := newHostLimiter()
	for _, address := range Addresses {
		logger.Debug(fmt.Sprintf("Deploying to address: %s", address.String()))
		wg.Add(1)
		sem.acquire()
		go func(addr string) {
			defer sem.release()
			runner.RunnerBf(addr, *Outfile, &wg)
		}(address.String())
	}
	wg.Wait()
	logger.Debug("useManualDeploy completed.")
	return nil
}

// hostLimiter caps how many hosts we hand off to SSH at once. Fanning out one
// goroutine per address is fine for a handful of hosts, but a /16 would open
// tens of thousands of concurrent TCP dials and SSH handshakes at once —
// exhausting file descriptors and thrashing rather than going faster. A bounded
// pool keeps a high, steady level of parallelism without the collapse.
type hostLimiter struct{ tokens chan struct{} }

func newHostLimiter() hostLimiter {
	max := *MaxHosts
	if max == 0 {
		// Zero removes the operator-selected soft cap, but never the absolute
		// process safety ceiling. This prevents a million-target expansion from
		// turning into a million simultaneous dials/goroutines.
		max = MaxHostConcurrency
	}
	return hostLimiter{tokens: make(chan struct{}, max)}
}

func (h hostLimiter) acquire() {
	if h.tokens != nil {
		h.tokens <- struct{}{}
	}
}

func (h hostLimiter) release() {
	if h.tokens != nil {
		<-h.tokens
	}
}
