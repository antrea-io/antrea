//go:build windows
// +build windows

// Copyright 2024 Antrea Authors
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

package secondarynetwork

import (
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

func (c *Controller) Initialize(stopCh <-chan struct{}) error {
	return nil
}

func (c *Controller) Restore() {
	// Not supported on Windows.
}

func (c *Controller) reconcileBridge() error {
	// Not supported on Windows.
	return nil
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	return
}

func resolveAndCreateOVSBridge(
	effectiveBridge func() *agenttypes.OVSBridgeConfig,
	ovsdbConn *ovsdb.OVSDB,
) (*agenttypes.OVSBridgeConfig, ovsconfig.OVSBridgeClient, error) {
	return nil, nil, nil
}
