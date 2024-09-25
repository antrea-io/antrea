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

type LinkEventHandler func(linkName string)

type Interface interface {
	LinkExists(linkName string) bool

	// Run starts the detector.
	Run(stopCh <-chan struct{})

	// AddEventHandler registers an eventHandler of link updates. It's not thread-safe and should be called before
	// starting the detector. If no link name is provided, the handler will be called for all link updates.
	AddEventHandler(handler LinkEventHandler, linkNames ...string)

	// HasSynced returns true if the cache has been initialized with the existing links.
	HasSynced() bool
}
