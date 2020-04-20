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

package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newCIDR(cidrStr string) *net.IPNet {
	_, tmpIpNet, _ := net.ParseCIDR(cidrStr)
	return tmpIpNet
}

func TestDiffCIDRs(t *testing.T) {
	testList := []*net.IPNet{newCIDR("10.20.0.0/16"),
		newCIDR("10.20.1.0/24"),
		newCIDR("10.20.2.0/28")}

	exceptList1 := []*net.IPNet{testList[1]}
	correctList1 := []*net.IPNet{newCIDR("10.20.128.0/17"),
		newCIDR("10.20.64.0/18"),
		newCIDR("10.20.32.0/19"),
		newCIDR("10.20.16.0/20"),
		newCIDR("10.20.8.0/21"),
		newCIDR("10.20.4.0/22"),
		newCIDR("10.20.2.0/23"),
		newCIDR("10.20.0.0/24")}

	diffCIDRs, err := DiffFromCIDRs(testList[0], exceptList1)
	if err != nil {
		t.Fatalf("diffFromCIDRs() error = %v", err)
	} else {
		assert.ElementsMatch(t, correctList1, diffCIDRs)
	}

	exceptList2 := []*net.IPNet{testList[1], testList[2]}
	correctList2 := []*net.IPNet{newCIDR("10.20.128.0/17"),
		newCIDR("10.20.64.0/18"),
		newCIDR("10.20.32.0/19"),
		newCIDR("10.20.16.0/20"),
		newCIDR("10.20.8.0/21"),
		newCIDR("10.20.4.0/22"),
		newCIDR("10.20.0.0/24"),
		newCIDR("10.20.3.0/24"),
		newCIDR("10.20.2.128/25"),
		newCIDR("10.20.2.64/26"),
		newCIDR("10.20.2.32/27"),
		newCIDR("10.20.2.16/28")}
	diffCIDRs, err = DiffFromCIDRs(testList[0], exceptList2)
	if err != nil {
		t.Fatalf("diffFromCIDRs() error = %v", err)
	} else {
		assert.ElementsMatch(t, correctList2, diffCIDRs)
	}

}

func TestMergeCIDRs(t *testing.T) {
	testList := []*net.IPNet{newCIDR("10.10.0.0/16"),
		newCIDR("10.20.0.0/16"),
		newCIDR("10.20.1.2/32"),
		newCIDR("10.20.1.3/32")}

	ipNetList0 := []*net.IPNet{testList[0], testList[1],
		testList[2], testList[3]}
	correctList0 := []*net.IPNet{testList[0], testList[1]}

	ipNetList0 = mergeCIDRs(ipNetList0)

	assert.ElementsMatch(t, correctList0, ipNetList0)

	ipNetList1 := []*net.IPNet{testList[0]}
	correctList1 := []*net.IPNet{testList[0]}

	ipNetList1 = mergeCIDRs(ipNetList1)
	assert.ElementsMatch(t, correctList1, ipNetList1)

	ipNetList2 := []*net.IPNet{testList[2], testList[3]}
	correctList2 := []*net.IPNet{testList[2], testList[3]}

	ipNetList2 = mergeCIDRs(ipNetList2)
	assert.ElementsMatch(t, correctList2, ipNetList2)

	ipNetList3 := []*net.IPNet{testList[0], testList[3]}
	correctList3 := []*net.IPNet{testList[0], testList[3]}

	ipNetList3 = mergeCIDRs(ipNetList3)
	assert.ElementsMatch(t, correctList3, ipNetList3)

	ipNetList4 := []*net.IPNet{}
	correctList4 := []*net.IPNet{}

	ipNetList4 = mergeCIDRs(ipNetList4)
	assert.ElementsMatch(t, correctList4, ipNetList4)
}
