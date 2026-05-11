package ssh

import (
	"testing"

	"github.com/LanodonF/coordinate-foister/internal/globals"
)

func TestCommandExecutionCommand(t *testing.T) {
	i := globals.Instance{Password: "secret"}

	tests := []struct {
		name    string
		command string
		ctx     hostExecutionContext
		want    string
	}{
		{
			name:    "plain command",
			command: "id",
			ctx:     hostExecutionContext{},
			want:    "id",
		},
		{
			name:    "sudo wrapped command",
			command: "id",
			ctx:     hostExecutionContext{wrapPayloadsWithSudo: true},
			want:    "echo \"secret\" | sudo -S bash -c 'id'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandExecutionCommand(tt.command, i, tt.ctx); got != tt.want {
				t.Fatalf("commandExecutionCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScriptExecutionCommand(t *testing.T) {
	i := globals.Instance{Password: "secret"}

	tests := []struct {
		name           string
		remoteFilename string
		ctx            hostExecutionContext
		want           string
	}{
		{
			name:           "plain script",
			remoteFilename: "/tmp/script",
			ctx:            hostExecutionContext{},
			want:           "/tmp/script ; rm /tmp/script",
		},
		{
			name:           "sudo wrapped script",
			remoteFilename: "/tmp/script",
			ctx:            hostExecutionContext{wrapPayloadsWithSudo: true},
			want:           "echo \"secret\" | sudo -S /tmp/script; sudo rm /tmp/script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scriptExecutionCommand(tt.remoteFilename, i, tt.ctx); got != tt.want {
				t.Fatalf("scriptExecutionCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveOutfile(t *testing.T) {
	i := globals.Instance{
		IP:       "10.10.20.5",
		Hostname: "web01",
		Outfile:  "%i%/%h%/%s%.out",
	}

	tests := []struct {
		name       string
		scriptName string
		want       string
	}{
		{name: "command placeholder", scriptName: "command", want: "10.10.20.5/web01/command.out"},
		{name: "script placeholder", scriptName: "inventory", want: "10.10.20.5/web01/inventory.out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveOutfile(i, tt.scriptName); got != tt.want {
				t.Fatalf("resolveOutfile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScriptOutfileName(t *testing.T) {
	tests := []struct {
		scriptPath string
		want       string
	}{
		{scriptPath: "inventory.sh", want: "inventory"},
		{scriptPath: "scripts/inventory.sh", want: "scripts/inventory"},
		{scriptPath: "inventory.bash", want: "inventory.bash"},
	}

	for _, tt := range tests {
		t.Run(tt.scriptPath, func(t *testing.T) {
			if got := scriptOutfileName(tt.scriptPath); got != tt.want {
				t.Fatalf("scriptOutfileName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewHostExecutionContext(t *testing.T) {
	tests := []struct {
		name     string
		instance globals.Instance
		output   []byte
		hostname string
		sudo     bool
		want     hostExecutionContext
	}{
		{
			name:     "valid shell with sudo wrapping",
			instance: globals.Instance{IP: "10.10.20.5", Username: "admin"},
			output:   []byte("a\n"),
			hostname: "web01",
			sudo:     true,
			want: hostExecutionContext{
				hostname:             "web01",
				shellValid:           true,
				wrapPayloadsWithSudo: true,
			},
		},
		{
			name:     "root never wraps sudo",
			instance: globals.Instance{IP: "10.10.20.6", Username: "root"},
			output:   []byte("a\n"),
			hostname: "db01",
			sudo:     true,
			want: hostExecutionContext{
				hostname:             "db01",
				shellValid:           true,
				wrapPayloadsWithSudo: false,
			},
		},
		{
			name:     "invalid shell falls back to ip hostname",
			instance: globals.Instance{IP: "10.10.20.7", Username: "admin"},
			output:   nil,
			hostname: "",
			sudo:     true,
			want: hostExecutionContext{
				hostname:             "10.10.20.7",
				shellValid:           false,
				wrapPayloadsWithSudo: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newHostExecutionContext(tt.instance, tt.output, tt.hostname, tt.sudo); got != tt.want {
				t.Fatalf("newHostExecutionContext() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
