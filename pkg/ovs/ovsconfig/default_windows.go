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
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultOVSRunDir = `C:\openvswitch\var\run\openvswitch`

	defaultConnNetwork = "winpipe"
	namedPipePrefix    = `\\.\pipe\`
	// Wait up to 5 seconds when getting port.
	defaultGetPortTimeout    = 5 * time.Second
	defaultOvsVersionMessage = "OVS version not found in ovsdb.  You might try running 'ovs-vsctl --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION'"
)

func GetConnAddress(ovsRunDir string) string {
	addr := filepath.Join(filepath.FromSlash(ovsRunDir), defaultOVSDBFile)
	addr = strings.Replace(addr, string(filepath.Separator), "", -1)
	return namedPipePrefix + addr
}
