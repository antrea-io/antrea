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

package proxy

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"antrea.io/antrea/pkg/agent/proxy/types"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

type serviceChangesTracker struct {
	tracker *k8sproxy.ServiceChangeTracker

	sync.Mutex
	initialized bool
}

func newServiceChangesTracker(ipFamily v1.IPFamily, serviceLabelSelector labels.Selector, skipServices []string) *serviceChangesTracker {
	tracker := k8sproxy.NewServiceChangeTracker(ipFamily, types.NewServiceInfo, nil, serviceLabelSelector, skipServices)
	return &serviceChangesTracker{tracker: tracker}
}

func (sh *serviceChangesTracker) OnServiceSynced() {
	sh.Lock()
	defer sh.Unlock()

	sh.initialized = true
}

func (sh *serviceChangesTracker) OnServiceUpdate(previous, current *v1.Service) bool {
	return sh.tracker.Update(previous, current)
}

func (sh *serviceChangesTracker) Synced() bool {
	sh.Lock()
	defer sh.Unlock()
	return sh.initialized
}

func (sh *serviceChangesTracker) Update(sm k8sproxy.ServicePortMap) k8sproxy.UpdateServiceMapResult {
	return sm.Update(sh.tracker)
}
