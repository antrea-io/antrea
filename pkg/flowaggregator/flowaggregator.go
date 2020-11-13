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

package flowaggregator

import (
	"net"
	"time"

	"github.com/vmware/go-ipfix/pkg/registry"
)

type flowAggregator struct {
	flowCollectorAddr net.Addr
	exportInterval    time.Duration
}

func InitFlowAggregator(flowCollectorAddr net.Addr, exportInterval time.Duration) *flowAggregator {
	registry.LoadRegistry()
	return &flowAggregator{
		flowCollectorAddr,
		exportInterval,
	}
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}) {
	// Place holder for Run() function, logic will be added in next PR
}
