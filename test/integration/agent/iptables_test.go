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
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/signals"
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
		expected := []struct {
			table  string
			output string
		}{
			{table: "filter", output: `:ANTREA-FORWARD - [0:0]
-A FORWARD -m comment --comment "Antrea: jump to Antrea forwarding rules" -j ANTREA-FORWARD
-A ANTREA-FORWARD -i gw0 -o gw0 -m comment --comment "Antrea: accept inter pod traffic" -j ACCEPT
-A ANTREA-FORWARD ! -i gw0 -o gw0 -m comment --comment "Antrea: accept external to pod traffic" -j ACCEPT
-A ANTREA-FORWARD -i gw0 ! -o gw0 -m comment --comment "Antrea: mark pod to external traffic" -j MARK --set-xmark 0x400/0x400
-A ANTREA-FORWARD -i gw0 ! -o gw0 -m comment --comment "Antrea: accept pod to external traffic" -j ACCEPT`},
			{table: "nat", output: `:ANTREA-POSTROUTING - [0:0]
-A POSTROUTING -m comment --comment "Antrea: jump to Antrea postrouting rules" -j ANTREA-POSTROUTING
-A ANTREA-POSTROUTING -m mark --mark 0x400/0x400 -m comment --comment "Antrea: masquerade traffic requiring SNAT" -j MASQUERADE`},
			{table: "mangle", output: `:ANTREA-MANGLE - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea mangle rule" -j ANTREA-MANGLE
-A ANTREA-MANGLE -d 1.1.0.0/16 -i gw0 -m comment --comment "Andrea: mark service traffic" -j MARK --set-xmark 0x800/0x800`},
		}

		for _, mode := range types.GetPodEncapModes() {
			signals.CleanupFns = nil
			t.Logf("Running test with Encap Mode %s", mode)
			nodeConfig := &types.NodeConfig{PodEncapMode: mode}
			curExpected := expected
			if !mode.SupportsNoEncap() {
				curExpected = expected[:2]
			} else {
				_, nodeConfig.ServiceCIDR, _ = net.ParseCIDR("1.1.0.0/16")
			}
			client, err := iptables.NewClient("gw0", nodeConfig)
			if err != nil {
				return fmt.Errorf("error creating iptables client: %v", err)
			}

			if err := client.SetupRules(); err != nil {
				return fmt.Errorf("error setting up rules: %v", err)
			}

			for _, exp := range curExpected {
				out, err := exec.Command(
					"bash", "-c", fmt.Sprintf("iptables-save -t %s | grep -i antrea", exp.table),
				).Output()
				if err != nil {
					return fmt.Errorf("error executing iptables-save : %v", err)
				}

				actualOutput := strings.TrimSpace(string(out))
				if !assert.Equal(t, exp.output, actualOutput) {
					return fmt.Errorf("iptables-save output doesn't match")
				}
			}

			for _, clean := range signals.CleanupFns {
				if err := clean(); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}
