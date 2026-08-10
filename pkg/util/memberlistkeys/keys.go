// Copyright 2026 Antrea Authors
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

// Package memberlistkeys handles the keys used to authenticate and encrypt the gossip traffic of the
// memberlist cluster formed by the antrea-agents. The keys are stored in a Secret, which is created
// by antrea-controller and read by every antrea-agent.
package memberlistkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/memberlist"

	"antrea.io/antrea/v2/pkg/apis"
)

// ParseKeys decodes the keys stored in the Secret. Keys are base64-encoded, one per line; empty
// lines are ignored, which makes it possible to format the Secret data with a trailing newline.
// The first key is the primary key.
//
// An error is returned if no key could be found, or if any key is invalid: we deliberately do not
// skip invalid keys, as silently ignoring one could lead to a Node using a different primary key
// than the rest of the cluster, which would partition the memberlist cluster.
func ParseKeys(data []byte) ([][]byte, error) {
	var keys [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// The index reported in the errors below is the index of the key, not of the line it was
		// read from, as empty lines are skipped.
		idx := len(keys)
		key, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("key at index %d is not valid base64: %w", idx, err)
		}
		// memberlist requires keys to be 16, 24 or 32 bytes long, for AES-128, AES-192 and AES-256
		// respectively.
		if err := memberlist.ValidateKey(key); err != nil {
			return nil, fmt.Errorf("key at index %d is invalid: %w", idx, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key found")
	}
	return keys, nil
}

// FormatKeys encodes keys so that they can be stored in the Secret. It is the inverse of ParseKeys.
func FormatKeys(keys [][]byte) []byte {
	encoded := make([]string, 0, len(keys))
	for _, key := range keys {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(key))
	}
	return []byte(strings.Join(encoded, "\n") + "\n")
}

// GenerateKey returns a new random key, suitable for use as a memberlist key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, apis.MemberlistKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}
