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

type eventHandler func(ip string, added bool)

type LocalIPDetector interface {
	IsLocalIP(ip string) bool

	// Run starts the detector.
	Run(stopCh <-chan struct{})

	// AddEventHandler registers an eventHandler of IP address update. It's not thread-safe and should be called before
	// starting the detector.
	AddEventHandler(handler eventHandler)

	// HasSynced returns true if the cache has been initialized with the full lists of IP addresses.
	HasSynced() bool
}
