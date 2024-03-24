// Copyright 2020 Antrea Authors

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

package env

import (
	"os"
	"testing"
)

func TestGetNodeName(t *testing.T) {
	hostName, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to retrieve hostname: %v", err)
	}
	testTable := map[string]string{
		"node1":     "node1",
		"node_12":   "node_12",
		"":          hostName,
		"node-1234": "node-1234",
	}

	for k, v := range testTable {
		t.Run("nodeName: "+k, func(t *testing.T) {
			if k != "" {
				t.Setenv(NodeNameEnvKey, k)
			}
			nodeName, err := GetNodeName()
			if err != nil {
				t.Errorf("Failure with expected name %s: %v", k, err)
				return
			}
			if nodeName != v {
				t.Errorf("Failed to retrieve nodename, want: %s, get: %s", v, nodeName)
			}
		})
	}
}

func TestGetPodName(t *testing.T) {
	testTable := map[string]string{
		"pod1":                               "pod1",
		"pod-1212-x":                         "pod-1212-x",
		"antrea-controller-577f4ffb4b-njprt": "antrea-controller-577f4ffb4b-njprt",
	}

	for k, v := range testTable {
		t.Run("podName: "+k, func(t *testing.T) {
			if k != "" {
				t.Setenv(podNameEnvKey, k)
			}
			podName := GetPodName()
			if podName != v {
				t.Errorf("Failed to retrieve pod name, want: %s, get: %s", v, podName)
			}
		})
	}
}

func TestGetAntreaConfigMapName(t *testing.T) {
	testTable := map[string]string{
		"antrea-config-asjqowieut": "antrea-config-asjqowieut",
		"antrea-config-x":          "antrea-config-x",
	}

	for k, v := range testTable {
		t.Run("config: "+k, func(t *testing.T) {
			if k != "" {
				t.Setenv(antreaConfigMapEnvKey, k)
			}
			configMapName := GetAntreaConfigMapName()
			if configMapName != v {
				t.Errorf("Failed to retrieve antrea configmap name, want: %s, get: %s", v, configMapName)
			}
		})
	}
}
