package metrics

import (
	"time"
	"reflect"
	"testing"
	"net"

	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	mock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
)

const (
	ovsBridge = "br-int"
)

func TestNewOVSStatManager(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	result := NewOVSStatManager(ovsBridge, ofClient)
	assert.Equal(t, result.ofClient, ofClient, "ofClient should be equal")
	assert.Equal(t, result.OVSBridge, ovsBridge, "OVSBridge should be equal")
	assert.NotEqual(t, result.OVSTableDesc, nil, "OVSTableDesc should be initialized")
}

func TestOVSStatManager_OVSGetStatistics(t *testing.T) {
	flowTable := []openflow.TableStatus{
		{0, 5, time.Now()},
		{40, 2, time.Now()},
	}
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ofClient.EXPECT().GetFlowTableStatus().Return(flowTable)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	expected := map[string]float64{"0": 5, "40": 2}
	if !reflect.DeepEqual(expected, ovsStatManager.OVSGetStatistics()) {
		t.Error("OVSGetStatistics not working correctly")
	}
}

func TestOVSStatManager_Collect(t *testing.T) {
	flowTable := []openflow.TableStatus{
		{0, 5, time.Now()},
	}
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ofClient.EXPECT().GetFlowTableStatus().Return(flowTable)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	out := make(chan prometheus.Metric)
	go ovsStatManager.Collect(out)
	desc := prometheus.NewDesc(
		"antrea_agent_ovs_flow_table",
		"OVS flow table flow count.",
		[]string{"table_id"},
		prometheus.Labels{"bridge": ovsBridge},
	)
	expected := prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 5, "0")
	assert.Equal(t, <-out, expected, "Collect should push the correct value")
}

func TestOVSStatManager_Describe(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	expected := prometheus.NewDesc(
		"antrea_agent_ovs_flow_table",
		"OVS flow table flow count.",
		[]string{"table_id"},
		prometheus.Labels{"bridge": ovsBridge},
	)
	out := make(chan *prometheus.Desc)
	go ovsStatManager.Describe(out)
	assert.Equal(t, <-out, expected, "Describe should assign the right value")
}

func TestStartListener(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	go StartListener(
		"0.0.0.0",
		9999,
		false,
		false,
		ovsBridge,
		interfacestore.NewInterfaceStore(),
		ofClient)
	time.Sleep(time.Second)
	conn, error := net.Dial("tcp", "0.0.0.0:9999")
	if error != nil {
		t.Error("Prometheus server does not start correctly")
	}
	defer conn.Close()
	// test prometheus register by duplicating register: if error -> item has already been registered
	gauge := prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "antrea_agent_local_pod_count",
			Help: "Testing",
		}, func() float64 { return 0 });
	gaugeHost := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "antrea_agent_host",
			Help: "Testing",
		})
	ovsStats := NewOVSStatManager("br-int", ofClient)
	registerPodCountError := prometheus.Register(gauge)
	if registerPodCountError == nil {
		t.Error("antrea_agent_local_pod_count has not been registered")
	}
	registerGaugeHostError := prometheus.Register(gaugeHost)
	if registerGaugeHostError == nil {
		t.Error("antrea_agent_host has not been registered")
	}
	registerOVSStatsError := prometheus.Register(ovsStats)
	if registerOVSStatsError == nil {
		t.Error("ovs_stats has not been registered")
	}
	registerGoError := prometheus.Register(prometheus.NewGoCollector())
	if registerGoError != nil {
		t.Error("Failed to unregister go metrics")
	}
	registerProcessError := prometheus.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	if registerProcessError != nil {
		t.Error("Failed to unregister process metrics")
	}
}
