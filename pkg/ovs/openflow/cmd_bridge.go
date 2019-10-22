// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"k8s.io/klog"
)

type commandBridge struct {
	sync.Mutex

	name       string
	tableCache map[TableIDType]Table
}

func (b *commandBridge) CreateTable(id, next TableIDType, missAction MissActionType) Table {
	t := &commandTable{
		bridge:     b.name,
		id:         id,
		next:       next,
		missAction: missAction,
	}
	b.Lock()
	defer b.Unlock()

	b.tableCache[t.id] = t
	return t
}

func (b *commandBridge) GetName() string {
	return b.name
}

func (b *commandBridge) DeleteTable(id TableIDType) bool {
	// TODO: no need to delete commandTable currently
	return true
}

func (b *commandBridge) DumpTableStatus() []TableStatus {
	var r []TableStatus
	for _, t := range b.tableCache {
		r = append(r, t.Status())
	}
	return r
}

// Connect initiates connection to the OFSwitch. commandBridge executes command "ovs-ofctl show" to check if target
// switch is connected or not.
func (b *commandBridge) Connect(maxRetry int, connectCh chan struct{}) error {
	for retry := 0; retry < maxRetry; retry++ {
		klog.V(2).Infof("Trying to connect to OpenFlow switch...")
		cmd := exec.Command("ovs-ofctl", "show", b.name)
		if err := cmd.Run(); err != nil {
			time.Sleep(1 * time.Second)
		} else {
			return nil
		}
	}
	return fmt.Errorf("failed to connect to OpenFlow switch after %d tries", maxRetry)
}

// Disconnect stops connection to the OFSwitch. commandBridge has no handling in Disconnect method.
func (b *commandBridge) Disconnect() error {
	return nil
}
