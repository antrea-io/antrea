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
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
)

func TestSetupRules(t *testing.T) {
	testNS, err := testutils.NewNS()
	if err != nil {
		t.Fatalf("Failed to create a network namespace")
	}
	defer func() {
		testNS.Close()
		testutils.UnmountNS(testNS)
	}()

	if err := testNS.Do(func(ns ns.NetNS) error {
		client, err := iptables.NewClient("gw0")
		if err != nil {
			return fmt.Errorf("error creating iptables client: %v", err)
		}
		if err := client.SetupRules(); err != nil {
			return fmt.Errorf("error setting up rules: %v", err)
		}

		expectedOutput := `:ANTREA-FORWARD - [0:0]
-A FORWARD -m comment --comment "Antrea: jump to Antrea forwarding rules" -j ANTREA-FORWARD
-A ANTREA-FORWARD -i gw0 -o gw0 -m comment --comment "Antrea: accept inter pod traffic" -j ACCEPT
-A ANTREA-FORWARD ! -i gw0 -o gw0 -m comment --comment "Antrea: accept external to pod traffic" -j ACCEPT
-A ANTREA-FORWARD -i gw0 ! -o gw0 -m comment --comment "Antrea: mark pod to external traffic" -j MARK --set-xmark 0x400/0x400
-A ANTREA-FORWARD -i gw0 ! -o gw0 -m comment --comment "Antrea: accept pod to external traffic" -j ACCEPT`
		out, err := exec.Command(
			"bash", "-c", "iptables-save -t filter | grep -i antrea",
		).Output()
		if err != nil {
			return fmt.Errorf("error executing iptables-save : %v", err)
		}

		actualOutput := strings.TrimSpace(string(out))
		if !assert.Equal(t, expectedOutput, actualOutput) {
			return fmt.Errorf("iptables-save output doesn't match")
		}

		expectedOutput = `:ANTREA-POSTROUTING - [0:0]
-A POSTROUTING -m comment --comment "Antrea: jump to Antrea postrouting rules" -j ANTREA-POSTROUTING
-A ANTREA-POSTROUTING -m mark --mark 0x400/0x400 -m comment --comment "Antrea: masquerade traffic requiring SNAT" -j MASQUERADE`
		out, err = exec.Command(
			"bash", "-c", "iptables-save -t nat | grep -i antrea",
		).Output()
		if err != nil {
			return fmt.Errorf("error executing iptables-save : %v", err)
		}

		actualOutput = strings.TrimSpace(string(out))
		if !assert.Equal(t, expectedOutput, actualOutput) {
			return fmt.Errorf("iptables-save output doesn't match")
		}

		return nil
	}); err != nil {
		t.Error(err)
	}
}
