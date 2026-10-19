package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "prints injected version and build date",
			args: []string{"version"},
			want: "version:    v1.2.3\nbuild date: 2026-10-19T10:00:00Z\n",
		},
		{
			name:    "rejects arguments",
			args:    []string{"version", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := newRootCmd("v1.2.3", "2026-10-19T10:00:00Z")
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, stdout.String())
			assert.Empty(t, stderr.String())
		})
	}
}
