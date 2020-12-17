package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/features"
)

func TestOptions_validateFlowExporterConfig(t *testing.T) {
	// Enable flow exporter
	enableFlowExporter := map[string]bool{
		"FlowExporter": true,
	}
	features.DefaultMutableFeatureGate.SetFromMap(enableFlowExporter)
	testcases := []struct {
		// input
		collector    string
		pollInterval string
		// expectations
		expCollectorNet    string
		expCollectorStr    string
		expPollIntervalStr string
		expError           error
	}{
		{collector: "192.168.1.100:2002:tcp", pollInterval: "5s", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "5s", expError: nil},
		{collector: "192.168.1.100:2002:udp", pollInterval: "5s", expCollectorNet: "udp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "5s", expError: nil},
		{collector: "192.168.1.100:2002", pollInterval: "5s", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "5s", expError: nil},
		{collector: "192.168.1.100:2002:sctp", pollInterval: "5s", expCollectorNet: "", expCollectorStr: "", expPollIntervalStr: "0s", expError: fmt.Errorf("connection over %s transport proto is not supported", "sctp")},
		{collector: "192.168.1.100:2002", pollInterval: "5ss", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "0s", expError: fmt.Errorf("FlowPollInterval is not provided in right format")},
		{collector: "192.168.1.100:2002", pollInterval: "1ms", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "0s", expError: fmt.Errorf("FlowPollInterval should be greater than or equal to one second")},
		{collector: "flow-aggregator.flow-aggregator.svc::tcp", pollInterval: "5s", expCollectorNet: "tcp", expCollectorStr: "flow-aggregator.flow-aggregator.svc:4739", expPollIntervalStr: "5s", expError: nil},
		{collector: "flow-aggregator.flow-aggregator.svc::sctp", pollInterval: "5s", expCollectorNet: "", expCollectorStr: "", expPollIntervalStr: "0s", expError: fmt.Errorf("connection over %s transport proto is not supported", "sctp")},
		{collector: ":abbbsctp::", pollInterval: "5s", expCollectorNet: "", expCollectorStr: "", expPollIntervalStr: "5s", expError: fmt.Errorf("flow collector address is given in invalid format")},
	}
	assert.Equal(t, features.DefaultFeatureGate.Enabled(features.FlowExporter), true)
	for _, tc := range testcases {
		testOptions := &Options{
			config: new(AgentConfig),
		}
		testOptions.config.FlowCollectorAddr = tc.collector
		testOptions.config.FlowPollInterval = tc.pollInterval
		err := testOptions.validateFlowExporterConfig()

		if tc.expError != nil {
			assert.Equalf(t, tc.expError, err, "not expected error for input: %v, %v", tc.collector, tc.pollInterval)
		} else {
			assert.Equalf(t, tc.expCollectorNet, testOptions.flowCollectorProto, "failed for input: %v, %v", tc.collector, tc.pollInterval)
			assert.Equalf(t, tc.expCollectorStr, testOptions.flowCollectorAddr, "failed for input: %v, %v", tc.collector, tc.pollInterval)
			assert.Equalf(t, tc.expPollIntervalStr, testOptions.pollInterval.String(), "failed for input: %v, %v", tc.collector, tc.pollInterval)
		}
	}
}

func TestParseFlowCollectorAddr(t *testing.T) {
	testcases := []struct {
		addr     string
		expected []string
	}{
		{
			"1.2.3.4:80:udp",
			[]string{"1.2.3.4", "80", "udp"},
		},
		{
			"1.2.3.4:80",
			[]string{"1.2.3.4", "80"},
		},
		{
			"[fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:80:tcp",
			[]string{"[fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", "80", "tcp"},
		},
	}
	for _, tc := range testcases {
		res, err := parseFlowCollectorAddr(tc.addr)
		assert.Nil(t, err)
		assert.Equal(t, tc.expected, res)
	}
}
