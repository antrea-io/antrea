// Copyright 2026 Antrea Authors
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

//go:build !linux

package ebpf

import (
	"fmt"
	"net"
)

// NewLoader returns a datapath which refuses to load, so that the packages wiring it in build everywhere.
// The feature gate is rejected on the platforms which land here, so Load is never reached.
func NewLoader() Interface {
	return &unsupported{}
}

type unsupported struct{}

func (u *unsupported) Load(config Config) error {
	return fmt.Errorf("the eBPF host datapath is only supported on Linux")
}

func (u *unsupported) Run(stopCh <-chan struct{})                           {}
func (u *unsupported) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error { return nil }
func (u *unsupported) DeletePodRoute(podCIDR *net.IPNet) error              { return nil }
func (u *unsupported) Stats() (Stats, error)                                { return Stats{}, nil }
func (u *unsupported) Close() error                                         { return nil }
