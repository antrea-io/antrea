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
	"k8s.io/client-go/tools/record"

	"antrea.io/antrea/pkg/agent/proxy/types"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

type serviceChangesTracker struct {
	tracker *k8sproxy.ServiceChangeTracker

	sync.Mutex
	initialized bool
}

func newServiceChangesTracker(recorder record.EventRecorder, isIPv6 bool) *serviceChangesTracker {
	return &serviceChangesTracker{tracker: k8sproxy.NewServiceChangeTracker(types.NewServiceInfo, &isIPv6, recorder)}
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

func (sh *serviceChangesTracker) Update(serviceMap k8sproxy.ServiceMap) k8sproxy.UpdateServiceMapResult {
	return k8sproxy.UpdateServiceMap(serviceMap, sh.tracker)
}
