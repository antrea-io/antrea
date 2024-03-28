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

	"antrea.io/antrea/pkg/apiserver/apis"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
)

type Config struct {
	// FeatureGates is a map of feature names to bools that enable or disable experimental features.
	FeatureGates map[string]bool `yaml:"featureGates,omitempty"`
}

const (
	AgentMode            = "agent"
	AgentWindowsMode     = "agent-windows"
	ControllerMode       = "controller"
	agentConfigName      = "antrea-agent.conf"
	controllerConfigName = "antrea-controller.conf"
)

// HandleFunc returns the function which can handle queries issued by 'antctl get featuregates' command.
// The handler function populates Antrea featuregates information to the response.
func HandleFunc(k8sclient clientset.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		antreaConfigMapName := env.GetAntreaConfigMapName()
		antreaNamespace := env.GetAntreaNamespace()
		antreaConfig, err := k8sclient.CoreV1().ConfigMaps(antreaNamespace).Get(context.TODO(), antreaConfigMapName, metav1.GetOptions{})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when getting config map", "ConfigMap", klog.KRef(antreaNamespace, antreaConfigMapName))
			return
		}
		configMaps, err := k8sclient.CoreV1().ConfigMaps(antreaNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=antrea",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when listing all Antrea ConfigMaps by label")
			return
		}
		antreaWindowsConfigMaps := []v1.ConfigMap{}
		for _, cm := range configMaps.Items {
			if strings.HasPrefix(cm.Name, "antrea-windows-config") {
				antreaWindowsConfigMaps = append(antreaWindowsConfigMaps, cm)
			}
		}

		agentConfig := &Config{}
		if err = yaml.Unmarshal([]byte(antreaConfig.Data[agentConfigName]), agentConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to unmarshal Antrea agent config",
				"ConfigMap", klog.KRef(antreaNamespace, antreaConfigMapName), "file", agentConfigName)
			return
		}

		controllerConfig := &Config{}
		if err = yaml.Unmarshal([]byte(antreaConfig.Data[controllerConfigName]), controllerConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to unmarshal Antrea controller config",
				"ConfigMap", klog.KRef(antreaNamespace, antreaConfigMapName), "file", controllerConfigName)
			return
		}

		agentfeatureGates := getFeatureGatesResponse(agentConfig, AgentMode)
		controllerfeatureGates := getFeatureGatesResponse(controllerConfig, ControllerMode)
		result := append(agentfeatureGates, controllerfeatureGates...)

		if len(antreaWindowsConfigMaps) > 0 {
			sort.Slice(antreaWindowsConfigMaps, func(i, j int) bool {
				return antreaWindowsConfigMaps[i].CreationTimestamp.After(antreaWindowsConfigMaps[j].CreationTimestamp.Time)
			})
			agentWindowsConfig := &Config{}
			antreaWindowsConfigMap := antreaWindowsConfigMaps[0]
			if err = yaml.Unmarshal([]byte(antreaWindowsConfigMap.Data[agentConfigName]), agentWindowsConfig); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				klog.ErrorS(err, "Failed to unmarshal Antrea agent windows config",
					"ConfigMap", klog.KRef(antreaNamespace, antreaWindowsConfigMap.Name), "file", agentConfigName)
				return
			}

			agentWindowsfeatureGates := getFeatureGatesResponse(agentWindowsConfig, AgentWindowsMode)
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

func getFeatureGatesResponse(cfg *Config, component string) []apis.FeatureGateResponse {
	gatesResp := []apis.FeatureGateResponse{}
	for df := range features.DefaultAntreaFeatureGates {
		if component == AgentMode && features.AgentGates.Has(df) ||
			component == AgentWindowsMode && features.AgentGates.Has(df) && features.SupportedOnWindows(df) ||
			component == ControllerMode && features.ControllerGates.Has(df) {

			status, ok := cfg.FeatureGates[string(df)]
			if !ok {
				status = features.DefaultFeatureGate.Enabled(df)
			}
			featureStatus := features.GetStatus(status)
			gatesResp = append(gatesResp, apis.FeatureGateResponse{
				Component: component,
				Name:      string(df),
				Status:    featureStatus,
				Version:   features.GetVersion(string(features.DefaultAntreaFeatureGates[df].PreRelease)),
			})
		}
	}
	sort.Slice(gatesResp, func(i, j int) bool {
		return gatesResp[i].Name < gatesResp[j].Name
	})
	return gatesResp
}
