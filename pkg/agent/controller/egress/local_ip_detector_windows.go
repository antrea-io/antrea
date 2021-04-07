// Copyright 2021 Antrea Authors
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

package egress

// Not implemented yet. The feature gate verification will protect this from being run.
type localIPDetector struct{}

func (d *localIPDetector) IsLocalIP(ip string) bool {
	return false
}

func (d *localIPDetector) Run(stopCh <-chan struct{}) {
	return
}

func (d *localIPDetector) AddEventHandler(handler eventHandler) {
	return
}

func (d *localIPDetector) HasSynced() bool {
	return false
}

func NewLocalIPDetector() *localIPDetector {
	return &localIPDetector{}
}
