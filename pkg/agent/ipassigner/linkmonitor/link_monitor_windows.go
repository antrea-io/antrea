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

package linkmonitor

type linkMonitor struct {
}

func NewLinkMonitor() *linkMonitor {
	return &linkMonitor{}
}

func (d *linkMonitor) HasSynced() bool {
	return false
}

func (d *linkMonitor) AddEventHandler(handler LinkEventHandler, linkNames ...string) {
}

func (d *linkMonitor) Run(stopCh <-chan struct{}) {
}

func (d *linkMonitor) LinkExists(name string) bool {
	return false
}
