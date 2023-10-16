package cmd_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/garethjevans/scm/pkg/cmd"
	"github.com/stretchr/testify/assert"
)

func TestTokenCmd_Run(t *testing.T) {
	tests := []struct {
		credentials        string
		host               string
		expected           string
		expectedErrMessage string
		expectedErr        bool
	}{
		{
			credentials: `https://user:token@github.com/`,
			host:        "https://github.com",
			expected:    "token",
		},
		{
			credentials: `https://user:token@github.com/
https://user:other@github.com/`,
			host:     "https://github.com",
			expected: "token",
		},
		{
			credentials: `https://user:token@github.com/
https://user:other@gitlab.com/`,
			host:     "https://github.com",
			expected: "token",
		},
		{
			credentials: `https://user:token@github.com/
https://user:other@gitlab.com/`,
			host:     "https://gitlab.com",
			expected: "other",
		},
		{
			credentials:        `https://user:other@gitlab.com/`,
			host:               "https://github.com",
			expected:           "",
			expectedErr:        true,
			expectedErrMessage: "Error: unable to locate a token for https://github.com",
		},
		{
			credentials: `https://user:token@gitlab.com/
https://user:other@gitlab.com/org/repo`,
			host:     "https://gitlab.com",
			expected: "token",
		},
		{
			credentials: `https://user:other@gitlab.com/org/repo
https://user:token@gitlab.com/`,
			host:     "https://gitlab.com",
			expected: "other",
		},
	}

	u := cmd.NewTokenCmd()

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			file, err := os.CreateTemp("", "test")
			assert.NoError(t, err)

			defer os.Remove(file.Name())

			// Example writing to the file
			text := []byte(tc.credentials)

			_, err = file.Write(text)
			assert.NoError(t, err)

			err = file.Close()
			assert.NoError(t, err)

			cmd.Path = file.Name()
			cmd.Host = tc.host

			stdout := bytes.NewBufferString("")
			u.SetOut(stdout)

			stderr := bytes.NewBufferString("")
			u.SetErr(stderr)

			err = u.Execute()
			if tc.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			actualOut, err := io.ReadAll(stdout)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, string(actualOut))

			actualErr, err := io.ReadAll(stderr)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedErrMessage, strings.TrimSpace(string(actualErr)))
		})
	}
}
