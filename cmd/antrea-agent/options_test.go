package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/features"
)

func TestOptionsValidateAntreaProxyConfig(t *testing.T) {
	feature := map[string]bool{string(features.AntreaProxy): true}
	err := features.DefaultMutableFeatureGate.SetFromMap(feature)
	require.NoError(t, err)
	require.True(t, features.DefaultFeatureGate.Enabled(features.AntreaProxy))
	for name, tc := range map[string]struct {
		virtualIPAddressConfig  string
		nodePortAddressesConfig []string
		expectedError           string
	}{
		"Valid case": {
			virtualIPAddressConfig:  defaultNodePortVirtualIP,
			nodePortAddressesConfig: []string{"10.10.0.1/80"},
		},
		"Invalid VirtualIPAddressConfig": {
			virtualIPAddressConfig:  "10.10.1.1",
			nodePortAddressesConfig: []string{"10.10.0.0/80"},
			expectedError:           "NodePortVirtualIP 10.10.1.1 is not an valid link-local IP address",
		},
		"Invalid NodePortAddresses": {
			virtualIPAddressConfig:  defaultNodePortVirtualIP,
			nodePortAddressesConfig: []string{"10.10.0.0"},
			expectedError:           "NodePortAddress is not valid, can not parse `10.10.0.0`: invalid CIDR address: 10.10.0.0",
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := newOptions()
			opts.config.NodePortVirtualIP = tc.virtualIPAddressConfig
			opts.config.NodePortAddresses = tc.nodePortAddressesConfig
			if len(tc.expectedError) > 0 {
				require.EqualError(t, opts.validateAntreaProxyConfig(), tc.expectedError)
			}
		})
	}
}

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
		{collector: "192.168.1.100:2002:sctp", pollInterval: "5s", expCollectorNet: "", expCollectorStr: "", expPollIntervalStr: "", expError: fmt.Errorf("IPFIX flow collector over %s proto is not supported", "sctp")},
		{collector: "192.168.1.100:2002", pollInterval: "5ss", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "", expError: fmt.Errorf("FlowPollInterval is not provided in right format: ")},
		{collector: "192.168.1.100:2002", pollInterval: "1ms", expCollectorNet: "tcp", expCollectorStr: "192.168.1.100:2002", expPollIntervalStr: "", expError: fmt.Errorf("FlowPollInterval should be greater than or equal to one second")},
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
			assert.NotNil(t, err)
		} else {
			assert.Equal(t, tc.expCollectorNet, testOptions.flowCollector.Network())
			assert.Equal(t, tc.expCollectorStr, testOptions.flowCollector.String())
			assert.Equal(t, tc.expPollIntervalStr, testOptions.pollInterval.String())
		}
	}

}
