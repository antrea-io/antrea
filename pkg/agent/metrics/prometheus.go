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

package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

// ovsStatManager implements prometheus.Collector
type ovsStatManager struct {
	ofClient     openflow.Client
	ovsBridge    string
	ovsTableDesc *prometheus.Desc
}

func (c *ovsStatManager) getOVSStatistics() (ovsFlowsByTable map[string]float64) {
	ovsFlowsByTable = make(map[string]float64)
	flowTableStatus := c.ofClient.GetFlowTableStatus()
	for _, tableStatus := range flowTableStatus {
		ovsFlowsByTable[strconv.Itoa(int(tableStatus.ID))] = float64(tableStatus.FlowCount)
	}
	return
}

func (c *ovsStatManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ovsTableDesc
}

func (c *ovsStatManager) Collect(ch chan<- prometheus.Metric) {
	ovsFlowsByTable := c.getOVSStatistics()
	for tableId, tableFlowCount := range ovsFlowsByTable {
		ch <- prometheus.MustNewConstMetric(
			c.ovsTableDesc,
			prometheus.GaugeValue,
			tableFlowCount,
			tableId,
		)
	}
}

func newOVSStatManager(ovsBridge string, ofClient openflow.Client) *ovsStatManager {
	return &ovsStatManager{
		ofClient:  ofClient,
		ovsBridge: ovsBridge,
		ovsTableDesc: prometheus.NewDesc(
			"antrea_agent_ovs_flow_table",
			"OVS flow table flow count.",
			[]string{"table_id"},
			prometheus.Labels{"bridge": ovsBridge},
		),
	}
}

func InitializePrometheusMetrics(
	ovsBridge string,
	ifaceStore interfacestore.InterfaceStore,
	ofClient openflow.Client) {

	klog.Info("Initializing prometheus metrics")
	prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "antrea_agent_local_pod_count",
			Help: "Number of pods on local node which are managed by the Antrea Agent.",
		},
		func() float64 { return float64(ifaceStore.GetContainerInterfaceNum()) },
	)

	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Errorf("Failed to retrieve agent K8S node name: %v", err)
	}

	gaugeHost := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "antrea_agent_runtime_info",
		Help:        "Antrea agent runtime info , defined as labels. The value of the gauge is always set to 1.",
		ConstLabels: prometheus.Labels{"k8s_nodename": nodeName, "k8s_podname": env.GetPodName()},
	})
	gaugeHost.Set(1)
	if err := prometheus.Register(gaugeHost); err != nil {
		klog.Error("Failed to register antrea_agent_runtime_info with Prometheus")
	}

	ovsStats := newOVSStatManager(ovsBridge, ofClient)
	if err := prometheus.Register(ovsStats); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_table with Prometheus")
	}
}
