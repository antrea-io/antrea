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
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
)

type (
	Config struct {
		// FeatureGates is a map of feature names to bools that enable or disable experimental features.
		FeatureGates map[string]bool `yaml:"featureGates,omitempty"`
	}

	Response struct {
		Component string `json:"component,omitempty"`
		Name      string `json:"name,omitempty"`
		Status    string `json:"status,omitempty"`
		Version   string `json:"version,omitempty"`
	}
)

const (
	agentMode            = "agent"
	agentWindowsMode     = "agent-windows"
	agentConfigName      = "antrea-agent.conf"
	controllerMode       = "controller"
	controllerConfigName = "antrea-controller.conf"
)

// HandleFunc returns the function which can handle queries issued by 'antctl get featuregates' command.
// The handler function populates Antrea featuregates information to the response.
func HandleFunc(k8sclient clientset.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		antreaConfigName := env.GetAntreaConfigMapName()
		antreaConfig, err := k8sclient.CoreV1().ConfigMaps(env.GetAntreaNamespace()).Get(context.TODO(), antreaConfigName, metav1.GetOptions{})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when getting config map", antreaConfigName)
			return
		}
		configMaps, err := k8sclient.CoreV1().ConfigMaps(env.GetAntreaNamespace()).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=antrea",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when getting antrea-windows config map")
			return
		}
		antreaWindowsConfigMaps := []v1.ConfigMap{}
		for _, cm := range configMaps.Items {
			if strings.HasPrefix(cm.Name, "antrea-windows-config") {
				antreaWindowsConfigMaps = append(antreaWindowsConfigMaps, cm)
			}
		}

		agentConfig := &Config{}
		err = yaml.Unmarshal([]byte(antreaConfig.Data[agentConfigName]), agentConfig)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to unmarshal Antrea", agentConfigName)
			return
		}

		controllerConfig := &Config{}
		err = yaml.Unmarshal([]byte(antreaConfig.Data[controllerConfigName]), controllerConfig)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to unmarshal Antrea", controllerConfigName)
			return
		}

		agentfeatureGates := getFeatureGatesResponse(agentConfig, agentMode)
		controllerfeatureGates := getFeatureGatesResponse(controllerConfig, controllerMode)
		result := append(agentfeatureGates, controllerfeatureGates...)

		if len(antreaWindowsConfigMaps) > 0 {
			sort.Slice(antreaWindowsConfigMaps, func(i, j int) bool {
				return antreaWindowsConfigMaps[i].CreationTimestamp.After(antreaWindowsConfigMaps[j].CreationTimestamp.Time)
			})
			agentWindowsConfig := &Config{}
			err = yaml.Unmarshal([]byte(configMaps.Items[0].Data[agentConfigName]), agentWindowsConfig)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				klog.ErrorS(err, "Failed to unmarshal Antrea windows", agentConfigName)
				return
			}
			agentWindowsfeatureGates := getFeatureGatesResponse(agentWindowsConfig, agentWindowsMode)
			result = append(result, agentWindowsfeatureGates...)
		}

		err = json.NewEncoder(w).Encode(result)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding FeatureGates to json")
			return
		}
	}
}

func getFeatureGatesResponse(cfg *Config, component string) []Response {
	gatesResp := []Response{}
	for df := range features.DefaultAntreaFeatureGates {
		if component == agentMode && features.AgentGates.Has(df) ||
			component == agentWindowsMode && features.AgentGates.Has(df) && features.SupportedOnWindows(df) ||
			component == controllerMode && features.ControllerGates.Has(df) {

			status, ok := cfg.FeatureGates[string(df)]
			if !ok {
				status = features.DefaultFeatureGate.Enabled(df)
			}
			featureStatus := getStatus(status)
			gatesResp = append(gatesResp, Response{
				Component: component,
				Name:      string(df),
				Status:    featureStatus,
				Version:   string(features.DefaultAntreaFeatureGates[df].PreRelease),
			})
		}
	}
	sort.SliceStable(gatesResp, func(i, j int) bool {
		return gatesResp[i].Name < gatesResp[j].Name
	})
	return gatesResp
}

func getStatus(status bool) string {
	if status {
		return "Enabled"
	}
	return "Disabled"
}
