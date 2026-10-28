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

package metrics

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/metrics/testutil"

	"antrea.io/antrea/v2/pkg/agent/ebpf"
)

// fakeHostDataPath is a ebpf.Interface whose counters are set by the test.
type fakeHostDataPath struct {
	stats    ebpf.Stats
	statsErr error
}

func (f *fakeHostDataPath) Load(config ebpf.Config) error                        { return nil }
func (f *fakeHostDataPath) Run(stopCh <-chan struct{})                           {}
func (f *fakeHostDataPath) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error { return nil }
func (f *fakeHostDataPath) DeletePodRoute(podCIDR *net.IPNet) error              { return nil }
func (f *fakeHostDataPath) Stats() (ebpf.Stats, error)                           { return f.stats, f.statsErr }
func (f *fakeHostDataPath) Close() error                                         { return nil }

func TestEBPFHostDataPathCollector(t *testing.T) {
	tests := []struct {
		name           string
		stats          ebpf.Stats
		statsErr       error
		expectedOutput string
	}{
		{
			name: "forwarded traffic",
			// Every field has a value of its own, so that a field exported under the wrong label fails.
			stats: ebpf.Stats{
				Forwarded:     1,
				Returned:      2,
				ForwardMisses: 3,
				ReturnMisses:  4,
				Passed:        5,
				TTLExpired:    6,
				TooBig:        7,
			},
			expectedOutput: `
# HELP antrea_agent_ebpf_host_datapath_packets_total [ALPHA] Number of packets seen by the eBPF host datapath, partitioned by what it did with them. Packets returned with TC_ACT_OK continue through the host network stack.
# TYPE antrea_agent_ebpf_host_datapath_packets_total counter
antrea_agent_ebpf_host_datapath_packets_total{result="forwarded"} 1
antrea_agent_ebpf_host_datapath_packets_total{result="returned"} 2
antrea_agent_ebpf_host_datapath_packets_total{result="forward_miss"} 3
antrea_agent_ebpf_host_datapath_packets_total{result="return_miss"} 4
antrea_agent_ebpf_host_datapath_packets_total{result="passed"} 5
antrea_agent_ebpf_host_datapath_packets_total{result="ttl_expired"} 6
antrea_agent_ebpf_host_datapath_packets_total{result="too_big"} 7
`,
		},
		{
			// The counters are left out rather than reported as zero, which would read as a reset.
			name:     "counters unreadable",
			statsErr: fmt.Errorf("bad file descriptor"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := newEBPFHostDataPathCollector(&fakeHostDataPath{stats: tt.stats, statsErr: tt.statsErr})
			err := testutil.CustomCollectAndCompare(collector, strings.NewReader(tt.expectedOutput),
				"antrea_agent_ebpf_host_datapath_packets_total")
			assert.NoError(t, err)
		})
	}
}
