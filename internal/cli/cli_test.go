package cli

import (
	"reflect"
	"testing"
)

func TestNormalizeOptionalKeyArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "short key path",
			args: []string{"-k", "~/.ssh/id_ed25519", "-x", "hostname"},
			want: []string{"-k=~/.ssh/id_ed25519", "-x", "hostname"},
		},
		{
			name: "long key path",
			args: []string{"--key", "/tmp/key", "-x", "hostname"},
			want: []string{"--key=/tmp/key", "-x", "hostname"},
		},
		{
			name: "short key without path",
			args: []string{"-k", "-x", "hostname"},
			want: []string{"-k", "-x", "hostname"},
		},
		{
			name: "attached short key path",
			args: []string{"-k/tmp/key"},
			want: []string{"-k=/tmp/key"},
		},
		{
			name: "explicit key assignment",
			args: []string{"-k=/tmp/key", "--key=/tmp/other"},
			want: []string{"-k=/tmp/key", "--key=/tmp/other"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeOptionalKeyArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeOptionalKeyArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}
