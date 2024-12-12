// Copyright 2024 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sftp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

func TestGetSSHClientConfig(t *testing.T) {
	const (
		user     = "foo"
		password = "bar"
	)
	rsaPubKey, _, err := sftptesting.GenerateRSAKey(4096)
	require.NoError(t, err)
	ed25519PubKey, _, err := sftptesting.GenerateEd25519Key()
	require.NoError(t, err)

	testCases := []struct {
		name                      string
		hostKey                   []byte
		expectedErr               string
		expectedHostKeyAlgorithms []string
		rsaKeyValid               bool
		ed25519KeyValid           bool
	}{
		{
			name:        "invalid key format",
			hostKey:     []byte("abc"),
			expectedErr: "invalid host public key",
		},
		{
			name:            "ignore host key",
			hostKey:         nil,
			rsaKeyValid:     true,
			ed25519KeyValid: true,
		},
		{
			name:                      "rsa key only",
			hostKey:                   rsaPubKey.Marshal(),
			expectedHostKeyAlgorithms: []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512},
			rsaKeyValid:               true,
			ed25519KeyValid:           false,
		},
		{
			name:                      "ed25519 key only",
			hostKey:                   ed25519PubKey.Marshal(),
			expectedHostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
			rsaKeyValid:               false,
			ed25519KeyValid:           true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := GetSSHClientConfig(user, password, tc.hostKey)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedHostKeyAlgorithms, cfg.HostKeyAlgorithms)
			require.NotNil(t, cfg.HostKeyCallback)
			rsaKeyValid := cfg.HostKeyCallback("", nil, rsaPubKey) == nil
			assert.Equal(t, tc.rsaKeyValid, rsaKeyValid, "Invalid HostKeyCallback result for RSA key")
			ed25519KeyValid := cfg.HostKeyCallback("", nil, ed25519PubKey) == nil
			assert.Equal(t, tc.ed25519KeyValid, ed25519KeyValid, "Invalid HostKeyCallback result for Ed25519 key")
		})
	}
}
