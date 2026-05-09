package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/LanodonF/coordinate-foister/internal/config"
	. "github.com/LanodonF/coordinate-foister/internal/globals"
	"github.com/LanodonF/coordinate-foister/internal/logger"
)

func Init() {
	logger.InitLogger()

	os.Args = append([]string{os.Args[0]}, normalizeOptionalKeyArgs(os.Args[1:])...)
	flag.Parse()

	Timeout = time.Duration(*Timelimit * int(time.Second))
	ShortTimeout = time.Duration(*Timelimit * 40 * int(time.Millisecond))

	Scripts = flag.Args()
	Commands = *Command

	if *TmpDir != "" {
		if _, err := os.Stat(*TmpDir); os.IsNotExist(err) {
			err := os.Mkdir(*TmpDir, 0777)
			if err != nil {
				logger.Err(fmt.Sprintf("Error creating tmp directory: %s", err))
			}
		}
	}
	if _, err := os.Stat("output"); os.IsNotExist(err) {
		err := os.Mkdir("output", 0777)
		if err != nil {
			logger.Err("Error creating output directory.")
		}
	}
}

func normalizeOptionalKeyArgs(args []string) []string {
	normalized := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-k" || arg == "--key":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				normalized = append(normalized, arg+"="+args[i+1])
				i++
			} else {
				normalized = append(normalized, arg)
			}
		case strings.HasPrefix(arg, "-k") && !strings.HasPrefix(arg, "-k="):
			normalized = append(normalized, "-k="+strings.TrimPrefix(arg, "-k"))
		default:
			normalized = append(normalized, arg)
		}
	}

	return normalized
}

func InputCheck() error {
	if (len(Scripts) == 0 && len(Commands) == 0 && *CreateConfig == "" && *ConfigOnly == "" && len(*DownloadDirs) == 0 && len(*UploadFiles) == 0) || ((*Usernames == "" || *Targets == "") && !*UseConfig) {
		return fmt.Errorf("Missing target(s), script(s)/command(s), and/or username(s).")
	}

	// Ensure scripts and commands are mutually exclusive
	if len(Scripts) > 0 && len(Commands) > 0 {
		return fmt.Errorf("Cannot specify both scripts and commands. Use either scripts or --command flag.")
	}

	if *CreateConfig != "" && *ConfigOnly == "" {
		*Environment = fmt.Sprintf("ROOTPASS=%s", *CreateConfig)
		if *IgnoreUsers != "" {
			*Environment += fmt.Sprintf(";IGNOREUSERS=%s", *IgnoreUsers)
		}
		if *AllPass != "" {
			*Environment += fmt.Sprintf(";ALLPASS=%s", *AllPass)
		}
		Scripts = nil
		Commands = nil
		Scripts = append(Scripts, "scripts/misc/password.sh")
	}

	if *Environment != "" {
		EnvironCmds = strings.Split(*Environment, ";")
	}

	config.ReadEnv()

	return nil
}

func PrintUsage() {
	fmt.Println("Usage:")
	flag.PrintDefaults()
}
