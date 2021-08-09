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
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/features"
)

func Test_getGatesResponse(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want []Response
	}{
		{
			name: "mutated AntreaPolicy feature gate, agent mode",
			cfg: &Config{
				FeatureGates: map[string]bool{
					"AntreaPolicy": false,
				},
			},
			want: []Response{
				{Component: "agent", Name: "AntreaPolicy", Status: "Disabled", Version: "BETA"},
				{Component: "agent", Name: "AntreaProxy", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "Egress", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "EndpointSlice", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "AntreaIPAM", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "FlowExporter", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "NodePortLocal", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "Multicast", Status: "Disabled", Version: "ALPHA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getAgentGatesResponse(tt.cfg)
			sort.SliceStable(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.SliceStable(tt.want, func(i, j int) bool {
				return tt.want[i].Name < tt.want[j].Name
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAgentGatesResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getStatus(t *testing.T) {
	tests := []struct {
		name   string
		status bool
		want   string
	}{
		{
			name:   "Enabled case",
			status: true,
			want:   "Enabled",
		},
		{
			name:   "Disabled case",
			status: false,
			want:   "Disabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getStatus(tt.status); got != tt.want {
				t.Errorf("getStatus() = %v, want %v", got, tt.want)
			}
		})
	}
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
	)

	tests := []struct {
		name             string
		expectedStatus   int
		expectedResponse []Response
	}{
		{
			name:           "good path",
			expectedStatus: http.StatusOK,
			expectedResponse: []Response{
				{Component: "controller", Name: "AntreaPolicy", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "Egress", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "NodeIPAM", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "AntreaPolicy", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "AntreaProxy", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "Egress", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "EndpointSlice", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "FlowExporter", Status: "Disabled", Version: "ALPHA"},
				{Component: "agent", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "agent", Name: "NodePortLocal", Status: "Enabled", Version: "BETA"},
			},
		},
	}
	os.Setenv("POD_NAME", "antrea-controller-wotqiwth")
	os.Setenv("ANTREA_CONFIG_MAP_NAME", "antrea-config-aswieut")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := HandleFunc(fakeClient)
			req, err := http.NewRequest(http.MethodGet, "", nil)
			assert.Nil(t, err)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}
			var resp []Response
			err = json.Unmarshal(recorder.Body.Bytes(), &resp)
			assert.Nil(t, err)
			for _, v := range resp {
				for n, f := range features.DefaultAntreaFeatureGates {
					if v.Name == string(n) {
						assert.Equal(t, v.Status, getStatus(f.Default))
						assert.Equal(t, v.Version, string(f.PreRelease))
					}
				}
			}
		})
	}
}

func Test_getControllerGatesResponse(t *testing.T) {
	tests := []struct {
		name string
		want []Response
	}{
		{
			name: "good path",
			want: []Response{
				{Component: "controller", Name: "AntreaPolicy", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "Egress", Status: "Disabled", Version: "ALPHA"},
				{Component: "controller", Name: "Traceflow", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "NetworkPolicyStats", Status: "Enabled", Version: "BETA"},
				{Component: "controller", Name: "NodeIPAM", Status: "Disabled", Version: "ALPHA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getControllerGatesResponse()
			sort.SliceStable(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.SliceStable(tt.want, func(i, j int) bool {
				return tt.want[i].Name < tt.want[j].Name
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getControllerGatesResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
