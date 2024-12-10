// Copyright 2024 Antrea Authors
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

package testing

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// GenerateRSAKey generates a RSA key pair. The public key is returned as a ssh.PublicKey. The
// private key is returned as PEM data, serialized in the OpenSSH format.
func GenerateRSAKey(bits int) (ssh.PublicKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publicKeySSH, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM, err := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKey), "")
	if err != nil {
		return nil, nil, err
	}
	return publicKeySSH, pem.EncodeToMemory(privateKeyPEM), nil
}

// GenerateRSAKey generates a ed25519 key pair. The public key is returned as a ssh.PublicKey. The
// private key is returned as PEM data, serialized in the OpenSSH format.
func GenerateEd25519Key() (ssh.PublicKey, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	publicKeySSH, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM, err := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKey), "")
	if err != nil {
		return nil, nil, err
	}
	return publicKeySSH, pem.EncodeToMemory(privateKeyPEM), nil
}
