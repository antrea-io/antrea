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
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/ebpf"
)

// The values of the result label of antrea_agent_ebpf_host_datapath_packets_total, one per field of
// ebpf.Stats.
const (
	LabelEBPFHostDataPathForwarded   = "forwarded"
	LabelEBPFHostDataPathReturned    = "returned"
	LabelEBPFHostDataPathForwardMiss = "forward_miss"
	LabelEBPFHostDataPathReturnMiss  = "return_miss"
	LabelEBPFHostDataPathPassed      = "passed"
	LabelEBPFHostDataPathTTLExpired  = "ttl_expired"
	LabelEBPFHostDataPathTooBig      = "too_big"
)

var (
	ebpfHostDataPathPacketsDesc = metrics.NewDesc(
		metrics.BuildFQName(metricNamespaceAntrea, metricSubsystemAgent, "ebpf_host_datapath_packets_total"),
		"Number of packets seen by the eBPF host datapath, partitioned by what it did with them. Packets returned "+
			"with TC_ACT_OK continue through the host network stack.",
		[]string{"result"},
		nil,
		metrics.ALPHA,
		"",
	)
)

// ebpfHostDataPathCollector reads the counters of the eBPF host datapath on every scrape. They live in a map
// the programs increment, so reading them when asked is what keeps them current without polling.
type ebpfHostDataPathCollector struct {
	metrics.BaseStableCollector

	ebpfClient ebpf.Interface
}

func newEBPFHostDataPathCollector(ebpfClient ebpf.Interface) *ebpfHostDataPathCollector {
	return &ebpfHostDataPathCollector{ebpfClient: ebpfClient}
}

func (c *ebpfHostDataPathCollector) DescribeWithStability(ch chan<- *metrics.Desc) {
	ch <- ebpfHostDataPathPacketsDesc
}

func (c *ebpfHostDataPathCollector) CollectWithStability(ch chan<- metrics.Metric) {
	stats, err := c.ebpfClient.Stats()
	if err != nil {
		klog.ErrorS(err, "Failed to read the counters of the eBPF host datapath")
		return
	}
	for _, counter := range []struct {
		result string
		value  uint64
	}{
		{LabelEBPFHostDataPathForwarded, stats.Forwarded},
		{LabelEBPFHostDataPathReturned, stats.Returned},
		{LabelEBPFHostDataPathForwardMiss, stats.ForwardMisses},
		{LabelEBPFHostDataPathReturnMiss, stats.ReturnMisses},
		{LabelEBPFHostDataPathPassed, stats.Passed},
		{LabelEBPFHostDataPathTTLExpired, stats.TTLExpired},
		{LabelEBPFHostDataPathTooBig, stats.TooBig},
	} {
		ch <- metrics.NewLazyConstMetric(ebpfHostDataPathPacketsDesc, metrics.CounterValue, float64(counter.value),
			counter.result)
	}
}

// InitializeEBPFHostDataPathMetrics registers the metrics of the eBPF host datapath. It is only called once the
// datapath loaded, as there is nothing to count otherwise.
func InitializeEBPFHostDataPathMetrics(ebpfClient ebpf.Interface) {
	if err := legacyregistry.CustomRegister(newEBPFHostDataPathCollector(ebpfClient)); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ebpf_host_datapath")
	}
}
