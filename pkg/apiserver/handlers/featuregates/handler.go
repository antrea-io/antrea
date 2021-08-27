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

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
)

var controllerOnlyGates = sets.NewString("Traceflow", "AntreaPolicy", "Egress", "NetworkPolicyStats")

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
	controllerMode = "controller"
	agentMode      = "agent"
)

// HandleFunc returns the function which can handle queries issued by 'antctl get featuregates' command.
// The handler function populates Antrea featuregates information to the response.
// For now, it will return all feature gates included in features.DefaultAntreaFeatureGates for agent
// We need to exclude any new feature gates which is not consumed by agent in the future.
func HandleFunc(k8sclient clientset.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		antreaConfigName := env.GetAntreaConfigMapName()
		antreaConfig, err := k8sclient.CoreV1().ConfigMaps(env.GetAntreaNamespace()).Get(context.TODO(), antreaConfigName, metav1.GetOptions{})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when getting config map %s: %v", antreaConfigName, err)
			return
		}

		agentConfig := &Config{}
		err = yaml.Unmarshal([]byte(antreaConfig.Data["antrea-agent.conf"]), agentConfig)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Failed to unmarshal Antrea antrea-agent.conf: %v", err)
			return
		}

		agentfeatureGates := getAgentGatesResponse(agentConfig)
		controllerfeatureGates := getControllerGatesResponse()
		result := append(agentfeatureGates, controllerfeatureGates...)
		err = json.NewEncoder(w).Encode(result)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding FeatureGates to json: %v", err)
			return
		}
	}
}

func getAgentGatesResponse(cfg *Config) []Response {
	gatesResp := []Response{}
	for df := range features.DefaultAntreaFeatureGates {
		dfs := string(df)
		status, ok := cfg.FeatureGates[dfs]
		if !ok {
			status = features.DefaultMutableFeatureGate.Enabled(df)
		}
		featureStatus := getStatus(status)
		gatesResp = append(gatesResp, Response{
			Component: agentMode,
			Name:      dfs,
			Status:    featureStatus,
			Version:   string(features.DefaultAntreaFeatureGates[df].PreRelease),
		})
	}
	return gatesResp
}

func getControllerGatesResponse() []Response {
	gatesResp := []Response{}
	for df := range features.DefaultAntreaFeatureGates {
		dfs := string(df)
		if !controllerOnlyGates.Has(dfs) {
			continue
		}
		gatesResp = append(gatesResp, Response{
			Component: controllerMode,
			Name:      dfs,
			Status:    getStatus(features.DefaultMutableFeatureGate.Enabled(df)),
			Version:   string(features.DefaultAntreaFeatureGates[df].PreRelease),
		})
	}
	return gatesResp
}

func getStatus(status bool) string {
	if status {
		return "Enabled"
	}
	return "Disabled"
}
