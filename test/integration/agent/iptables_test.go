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

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
)

func TestSetupRules(t *testing.T) {
	testNS, err := testutils.NewNS()
	if err != nil {
		t.Fatalf("Failed to create a network namespace")
	}
	defer func() {
		_ = testNS.Close()
		_ = testutils.UnmountNS(testNS)
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
-A ANTREA-MANGLE -d 1.1.0.0/16 -i gw0 -m comment --comment "Antrea: mark service traffic" -j MARK --set-xmark 0x800/0x800`},
			{table: "raw", output: `:ANTREA-RAW - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea raw rule" -j ANTREA-RAW
-A ANTREA-RAW -i gw0 -m mac --mac-source DE:AD:BE:EF:DE:AD -m comment --comment "Antrea: reentry pod traffic skip conntrack" -j CT --notrack`},
		}

		modes := config.GetTrafficEncapModes()
		modes = append(modes, config.TrafficEncapModeEncap) // add one more to test reconcile logic

		for _, mode := range modes {
			t.Logf("Running test with Encap Mode %s", mode)
			nodeConfig := &config.NodeConfig{}
			curExpected := expected
			if !mode.SupportsNoEncap() {
				curExpected = expected[:2]
			}
			_, serviceCIDR, _ = net.ParseCIDR("1.1.0.0/16")

			client := iptables.NewClient("gw0", serviceCIDR, mode)
			if err := client.Initialize(nodeConfig); err != nil {
				return fmt.Errorf("error setting up rules: %v", err)
			}

			if err := client.Reconcile(); err != nil {
				// time.Sleep(3600 * time.Second)
				return fmt.Errorf("error reconcile rules: %v", err)
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

			if len(expected) == len(curExpected) {
				continue
			}
			notCurExpected := expected[len(curExpected):]
			for _, exp := range notCurExpected {
				out, err := exec.Command(
					"bash", "-c", fmt.Sprintf("iptables-save -t %s | grep -i antrea", exp.table),
				).Output()
				if err == nil {
					return fmt.Errorf("unexpected rule found %s", out)
				}
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}
