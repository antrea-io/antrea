// Copyright 2019 Antrea Authors
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

package agent

import (
	"os"
	"testing"
)

func TestGetNodeName(t *testing.T) {
	hostName, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to retrieve hostname, %v", err)
	}
	testTable := map[string]string{
		"node1":     "node1",
		"node_12":   "node_12",
		"":          hostName,
		"node-1234": "node-1234",
	}

	for k, v := range testTable {
		compareNodeName(k, v, t)
	}
}

func compareNodeName(k, v string, t *testing.T) {
	if k != "" {
		_ = os.Setenv(NodeNameEnvKey, k)
		defer os.Unsetenv(NodeNameEnvKey)
	}
	nodeName, err := getNodeName()
	if err != nil {
		t.Errorf("Failure with expected name %s, %v", k, err)
		return
	}
	if nodeName != v {
		t.Errorf("Failed to retrieve nodename, want: %s, get: %s", v, nodeName)
	}
}
