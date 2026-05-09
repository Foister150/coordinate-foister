package runner

import (
	"testing"

	flag "github.com/spf13/pflag"

	. "github.com/LanodonF/coordinate-foister/internal/globals"
)

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
