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

package featuregates

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/featuregate"

	"antrea.io/antrea/pkg/apiserver/apis"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/runtime"
)

var (
	egressStatus    string
	multicastStatus string
)

func Test_getGatesResponse(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want []apis.FeatureGateResponse
	}{
		{
			name: "mutated AntreaPolicy feature gate, agent mode",
			cfg: &Config{
				FeatureGates: map[string]bool{
					"AntreaPolicy": false,
				},
			},
			want: []apis.FeatureGateResponse{
				{Component: "agent", Name: "AntreaIPAM", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "AntreaPolicy", Status: "Disabled", Version: "BETA"},
				{Component: "agent", Name: "AntreaProxy", Status: "Enabled", Version: "GA"},
				{Component: "agent", Name: "CleanupStaleUDPSvcConntrack", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "Egress", Status: egressStatus, Version: "BETA"},
				{Component: "agent", Name: "EgressSeparateSubnet", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "EgressTrafficShaping", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "EndpointSlice", Status: "Enabled", Version: "GA"},
				{Component: "agent", Name: "ExternalNode", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "FlowExporter", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "IPsecCertAuth", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "L7FlowExporter", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "L7NetworkPolicy", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "LoadBalancerModeDSR", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "Multicast", Status: multicastStatus, Version: "BETA"},
				{Component: "agent", Name: "Multicluster", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "NodeNetworkPolicy", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "NodePortLocal", Status: "Enabled", Version: "GA"},
				{Component: "agent", Name: "SecondaryNetwork", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "ServiceExternalIP", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "SupportBundleCollection", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "TopologyAwareHints", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "TrafficControl", Status: "Disabled", Version: "ALPHA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFeatureGatesResponse(tt.cfg, AgentMode)
			assert.Equal(t, got, tt.want, "The feature gates for Antrea agent are not correct")
		})
	}
}

func Test_getGatesWindowsResponse(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want []apis.FeatureGateResponse
	}{
		{
			name: "mutated AntreaPolicy feature gate, agent windows mode",
			cfg: &Config{
				FeatureGates: map[string]bool{
					"AntreaPolicy": false,
				},
			},
			want: []apis.FeatureGateResponse{
				{Component: "agent-windows", Name: "AntreaPolicy", Status: "Disabled", Version: "BETA"},
				{Component: "agent-windows", Name: "AntreaProxy", Status: "Enabled", Version: "GA"},
				{Component: "agent-windows", Name: "EndpointSlice", Status: "Enabled", Version: "GA"},
				{Component: "agent-windows", Name: "ExternalNode", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent-windows", Name: "FlowExporter", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent-windows", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "agent-windows", Name: "NodePortLocal", Status: "Enabled", Version: "GA"},
				{Component: "agent-windows", Name: "SupportBundleCollection", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent-windows", Name: "TopologyAwareHints", Status: "Enabled", Version: "BETA"},
				{Component: "agent-windows", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "agent-windows", Name: "TrafficControl", Status: "Disabled", Version: "ALPHA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFeatureGatesResponse(tt.cfg, AgentWindowsMode)
			assert.Equal(t, got, tt.want, "The feature gates for Antrea agent windows are not correct")
		})
	}
}

func TestGetStatus(t *testing.T) {
	assert.Equal(t, "Enabled", features.GetStatus(true))
	assert.Equal(t, "Disabled", features.GetStatus(false))
}

func TestHandleFunc(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "antrea-controller-wotqiwth",
				Namespace: "kube-system",
			},
			Spec: v1.PodSpec{
				Volumes: []v1.Volume{{
					Name: "antrea-config",
					VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: "antrea-config-aswieut",
						},
					}},
				}}},
		},
		&v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "antrea-config-aswieut"},
			Data: map[string]string{
				"antrea-agent.conf":      "#configmap-value",
				"antrea-controller.conf": "#configmap-value",
			},
		},
		&v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "antrea-windows-config-xqwiwuv", Labels: map[string]string{"app": "antrea"}},
			Data: map[string]string{
				"antrea-agent.conf": "#configmap-value",
			},
		},
	)

	t.Setenv("POD_NAME", "antrea-controller-wotqiwth")
	t.Setenv("ANTREA_CONFIG_MAP_NAME", "antrea-config-aswieut")

	handler := HandleFunc(fakeClient)
	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)

	var resp []apis.FeatureGateResponse
	err = json.Unmarshal(recorder.Body.Bytes(), &resp)
	require.Nil(t, err)

	for _, v := range resp {
		df, ok := features.DefaultAntreaFeatureGates[featuregate.Feature(v.Name)]
		require.True(t, ok)
		assert.Equal(t, v.Status, features.GetStatus(df.Default))
		assert.Equal(t, v.Version, features.GetVersion(string(df.PreRelease)))
	}
}

func Test_getControllerGatesResponse(t *testing.T) {
	tests := []struct {
		name string
		want []apis.FeatureGateResponse
	}{
		{
			name: "good path",
			want: []apis.FeatureGateResponse{
				{Component: "controller", Name: "AdminNetworkPolicy", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "AntreaIPAM", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "AntreaPolicy", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "Egress", Status: egressStatus, Version: "BETA"},
				{Component: "controller", Name: "IPsecCertAuth", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "L7NetworkPolicy", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "Multicast", Status: multicastStatus, Version: "BETA"},
				{Component: "controller", Name: "Multicluster", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "NodeIPAM", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "ServiceExternalIP", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "SupportBundleCollection", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFeatureGatesResponse(&Config{}, ControllerMode)
			assert.Equal(t, got, tt.want, "The feature gates for Antrea Controller are not correct")
		})
	}
}

func init() {
	egressStatus = "Enabled"
	multicastStatus = "Enabled"
	if runtime.IsWindowsPlatform() {
		egressStatus = "Disabled"
		multicastStatus = "Disabled"
	}
}
