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

package ovsconfig

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	ofconfig "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	ovsRunDirWin      = `C:\openvswitch\var\run\openvswitch`
	ovsRunDirWinSlash = `C:/openvswitch/var/run/openvswitch`
	ovsRunDirUnix     = `/var/run/openvswitch`
)

func TestGetOVSDBConnNetAddress(t *testing.T) {
	if runtime.GOOS == "windows" {
		expectedAddr := `\\.\pipe\C:openvswitchvarrunopenvswitchdb.sock`
		addr := GetConnAddress(ovsRunDirWin)
		assert.Equal(t, expectedAddr, addr)

		addr = GetConnAddress(ovsRunDirWinSlash)
		assert.Equal(t, expectedAddr, addr)
	} else {
		expectedAddr := "/var/run/openvswitch/db.sock"
		addr := GetConnAddress(ovsRunDirUnix)
		assert.Equal(t, expectedAddr, addr)
	}
}

func TestGetOVSMgmtAddress(t *testing.T) {
	brName := "br"
	if runtime.GOOS == "windows" {
		expectedAddr := `\\.\pipe\C:openvswitchvarrunopenvswitchbr.mgmt`
		mgmtAddr := ofconfig.GetMgmtAddress(ovsRunDirWin, brName)
		assert.Equal(t, expectedAddr, mgmtAddr)

		mgmtAddr = ofconfig.GetMgmtAddress(ovsRunDirWinSlash, brName)
		assert.Equal(t, expectedAddr, mgmtAddr)
	} else {
		expectedAddr := `/var/run/openvswitch/br.mgmt`
		mgmtAddr := ofconfig.GetMgmtAddress(ovsRunDirUnix, brName)
		assert.Equal(t, expectedAddr, mgmtAddr)
	}
}
