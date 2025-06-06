package http

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf/config"
)

func TestKDF(t *testing.T) {
	tests := []struct {
		algorithm  string
		password   string
		salt       string
		iterations int
		length     int
		key        string
		iv         string
	}{
		{
			algorithm:  "PBKDF2-HMAC-SHA256",
			password:   "a secret password",
			salt:       "somerandombytes",
			iterations: 2000,
			length:     16,
			key:        "f49817e5faa63d9bb631b143c7d11ff7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			cfg := kdfConfig{
				Algorithm:  tt.algorithm,
				Passwd:     config.NewSecret([]byte(tt.password)),
				Salt:       config.NewSecret([]byte(tt.salt)),
				Iterations: tt.iterations,
			}
			skey, siv, err := cfg.newKey(16)
			require.NoError(t, err)
			require.NotNil(t, skey)
			require.NotNil(t, siv)

			key, err := skey.Get()
			require.NoError(t, err)
			defer key.Destroy()
			require.Equal(t, tt.key, key.TemporaryString())

			if tt.iv != "" {
				iv, err := siv.Get()
				require.NoError(t, err)
				defer iv.Destroy()
				require.Equal(t, tt.iv, iv.TemporaryString())
			} else {
				require.True(t, siv.Empty())
			}
		})
	}
}

func TestKDFErrors(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		salt       string
		iterations int
		length     int
		expected   string
	}{
		{
			name:     "missing iterations",
			password: "a secret password",
			salt:     "somerandombytes",
			length:   16,
			expected: "iteration value not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEmpty(t, tt.expected)

			cfg := kdfConfig{
				Algorithm:  "PBKDF2-HMAC-SHA256",
				Passwd:     config.NewSecret([]byte(tt.password)),
				Salt:       config.NewSecret([]byte(tt.salt)),
				Iterations: tt.iterations,
			}
			_, _, err := cfg.newKey(16)
			require.ErrorContains(t, err, tt.expected)
		})
	}
}
