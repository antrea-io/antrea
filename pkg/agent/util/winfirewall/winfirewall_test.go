// +build windows

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

package winfirewall

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWinFirewallRules(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("2.2.2.0/24")

	client := NewClient()

	checkExistence := func(rules []string, expectExists bool) {
		for _, ruleName := range rules {
			exists, err := client.FirewallRuleExists(ruleName)
			require.Nil(t, err)
			assert.Equal(t, expectExists, exists)
		}
	}

	inRule := "in-rule"
	outRule := "out-rule"
	expectedRules := []string{inRule, outRule}
	checkExistence(expectedRules, false)
	err := client.AddRuleAllowIP(inRule, FWRuleIn, podCIDR)
	require.Nil(t, err)
	err = client.AddRuleAllowIP(outRule, FWRuleOut, podCIDR)
	require.Nil(t, err)
	checkExistence(expectedRules, true)

	err = client.DelFirewallRuleByName(inRule)
	require.Nil(t, err)
	err = client.DelFirewallRuleByName(outRule)
	require.Nil(t, err)
	checkExistence(expectedRules, false)
}
