package main

import (
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
	logger.Debug("Starting the application...")

	cli.Init()
	logger.Debug("CLI initialization completed.")
	err := cli.InputCheck()
	if err != nil {
		logger.Err(err)
		cli.PrintUsage()
		return
	}
	if err := preloadScripts(); err != nil {
		logger.Fatal(err)
	}

	logger.Debug(fmt.Sprintf("UseConfig flag: %v", *UseConfig))
	if *UseConfig {
		useConfigDeploy()
	} else {
		prepareManualDeploy()
	}
	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	logger.Debug(fmt.Sprintf("Key: %s, PasswordList length: %d", *Key, len(PasswordList)))
	if runner.KeyAuthEnabled() || len(PasswordList) != 0 {
		useManualDeploy()
	}

	brokenHosts := BrokenHostsSnapshot()
	if len(brokenHosts) != 0 {
		logger.Debug(fmt.Sprintf("BrokenHosts detected: %v", brokenHosts))
		printBrokenHosts(brokenHosts)
	}

	if *CreateConfig != "" || *ConfigOnly != "" {
		logger.Debug("CreateConfig flag detected. Saving config...")
		config.SaveConfig()
	}

	annoyingErrs := AnnoyingErrsSnapshot()
	if len(annoyingErrs) > 0 {
		logger.Debug("Processing AnnoyingErrs...")
		for _, conerr := range annoyingErrs {
			logger.Err(conerr)
		}
	}

	logger.Info(fmt.Sprintf("Total hosts hit: %d\n", TotalRunsValue()))
	logger.Debug("Application execution completed.")
}

func preloadScripts() error {
	for _, path := range Scripts {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read script %q: %w", path, err)
		}
		ScriptContentsMap[path] = string(data)
	}
	return nil
}

func useConfigDeploy() {
	logger.Debug("Starting useConfigDeploy...")
	config.ReadConfig()

	configEntries := config.ConfigEntriesSnapshot()
	if len(configEntries) == 0 {
		logger.Err("No entries in config file")
		return
	}

	logger.Debug(fmt.Sprintf("Config entries found: %d", len(configEntries)))
	tempConfigEntries := configEntries

	if *Targets != "" {
		logger.Debug("Filtering config entries based on specified targets...")
		var err error
		Addresses, _, err = utils.ParseIPs(*Targets)
		if err != nil {
			logger.Err(fmt.Sprintf("Error parsing targets: %s", err))
			return
		}

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
	}

	var sem chan struct{}
	if *MaxHosts > 0 {
		sem = make(chan struct{}, *MaxHosts)
	}

	var wg sync.WaitGroup
	for _, entry := range tempConfigEntries {
		logger.Debug(fmt.Sprintf("Running config entry: %+v", entry))
		if sem != nil {
			sem <- struct{}{}
		}
		wg.Add(1)
		go func(entry config.ConfigEntry) {
			defer func() {
				if sem != nil {
					<-sem
				}
			}()
			runner.RunnerCred(entry.IP, *Outfile, &wg, entry.Username, entry.Password)
		}(entry)
	}
	wg.Wait()
	logger.Debug("useConfigDeploy completed.")
}

func prepareManualDeploy() {
	logger.Debug("Starting prepareManualDeploy...")

	var err error
	Addresses, StringAddresses, err = utils.ParseIPs(*Targets)

	if err != nil {
		logger.Err(fmt.Sprintf("Error parsing targets: %s", err))
		return
	}

	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	if !*QuietOut {
		fmt.Printf("Specified targets (%d addresses):\n\t%s\n", len(Addresses), strings.Join(StringAddresses, "\n\t"))
		if len(Scripts) > 0 {
			fmt.Printf("Specified scripts (%d files):\n\t%s\n", len(Scripts), strings.Join(Scripts, "\n\t"))
		}
		if len(Commands) > 0 {
			fmt.Printf("Specified commands (%d commands):\n\t%s\n", len(Commands), strings.Join(Commands, "\n\t"))
		}
		if len(EnvironCmds) != 0 {
			fmt.Printf("Specified environmental commands (%d items):\n\t%s\n", len(EnvironCmds), strings.Join(EnvironCmds, "\n\t"))
		}
	}

	UsernameList = strings.Split(*Usernames, ",")
	logger.Debug(fmt.Sprintf("Parsed usernames: %v", UsernameList))

	if *Passwords == "" && *CreateConfig == "" && !runner.KeyAuthEnabled() {
		fmt.Print("Password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logger.Fatal(err)
		}
		PasswordList = []string{strings.TrimSpace(string(password))}
		fmt.Println()
		logger.Debug("Password read from terminal.")
	} else if *Passwords != "" {
		PasswordList = strings.Split(*Passwords, ",")
		logger.Debug(fmt.Sprintf("Parsed passwords: %v", PasswordList))
	} else if *Key != "" && *Key != AgentKeyFlagValue {
		_, err = os.ReadFile(strings.TrimSpace(*Key))
		if err != nil {
			logger.Fatal(err)
		}
		logger.Debug(fmt.Sprintf("Key file found: %s", *Key))
	}
	logger.Debug(fmt.Sprintf("Parsed %d IP addresses.", len(Addresses)))
	logger.Debug("prepareManualDeploy completed.")
}

func useManualDeploy() {
	logger.Debug("Starting useManualDeploy...")

	if len(Addresses) == 0 {
		logger.Err("No addresses to deploy. Ensure target IPs are parsed correctly.")
		return
	}

	var sem chan struct{}
	if *MaxHosts > 0 {
		sem = make(chan struct{}, *MaxHosts)
	}

	var wg sync.WaitGroup
	for _, address := range Addresses {
		logger.Debug(fmt.Sprintf("Deploying to address: %s", address.String()))
		if sem != nil {
			sem <- struct{}{}
		}
		wg.Add(1)
		go func(addr string) {
			defer func() {
				if sem != nil {
					<-sem
				}
			}()
			runner.RunnerBf(addr, *Outfile, &wg)
		}(address.String())
	}
	wg.Wait()
	logger.Debug("useManualDeploy completed.")
}

func printBrokenHosts(hosts []string) {
	logger.Debug("Printing broken hosts...")
	logger.Err("The following hosts had janky ssh and should be configured manually:")
	for _, host := range hosts {
		logger.Err(host)
	}
	logger.Debug("Broken hosts printed.")
}
