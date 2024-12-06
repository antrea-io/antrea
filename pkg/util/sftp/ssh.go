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
	"golang.org/x/crypto/ssh"
)

// GetAlgorithmsForHostKey returns the list of supported key algorithms for a given public key. In
// most cases, there is a single algorithms, which matches the key type. This is useful when setting
// the HostKeyCallback in ssh.ClientConfig to accept a fixed host key. The server may support
// multiple key types / key algorithms, and if we use the default value for HostKeyAlgorithms, the
// server may present a key that does not match our HostKeyCallback. When using a fixed host key, it
// makes sense to set HostKeyAlgorithms to the list of algorithms matching that specific key type.
func GetAlgorithmsForHostKey(key ssh.PublicKey) []string {
	switch t := key.Type(); t {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	default:
		return []string{t}
	}
}
