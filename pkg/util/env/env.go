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

package env

import (
	"os"
	"strconv"

	"k8s.io/klog/v2"
)

// nodeNameEnvKey is environment variable.
const (
	nodeNameEnvKey     = "NODE_NAME"
	podNameEnvKey      = "POD_NAME"
	podNamespaceEnvKey = "POD_NAMESPACE"

	antreaCloudEKSEnvKey = "ANTREA_CLOUD_EKS"
)

// GetNodeName returns the node's name used in Kubernetes, based on the priority:
// - Environment variable NODE_NAME, which should be set by Downward API
// - OS's hostname
func GetNodeName() (string, error) {
	nodeName := os.Getenv(nodeNameEnvKey)
	if nodeName != "" {
		return nodeName, nil
	}
	klog.Infof("Environment variable %s not found, using hostname instead", nodeNameEnvKey)
	var err error
	nodeName, err = os.Hostname()
	if err != nil {
		klog.Errorf("Failed to get local hostname: %v", err)
		return "", err
	}
	return nodeName, nil
}

// GetPodName returns name of the Pod where the code executes.
func GetPodName() string {
	podName := os.Getenv(podNameEnvKey)
	if podName == "" {
		klog.Warningf("Environment variable %s not found", podNameEnvKey)
	}
	return podName
}

// GetPodNamespace returns Namespace of the Pod where the code executes.
func GetPodNamespace() string {
	podNamespace := os.Getenv(podNamespaceEnvKey)
	if podNamespace == "" {
		klog.Warningf("Environment variable %s not found", podNamespaceEnvKey)
	}
	return podNamespace
}

func getBoolEnvVar(name string, defaultValue bool) bool {
	if strValue := os.Getenv(name); strValue != "" {
		parsedValue, err := strconv.ParseBool(strValue)
		if err != nil {
			klog.Errorf("Failed to parse env variable '%s' (using default '%t'): %v", name, defaultValue, err)
			return defaultValue
		}
		return parsedValue
	}
	return defaultValue
}

// Returns true if Antrea is used to enforce NetworkPolicies in an EKS cluster.
func IsCloudEKS() bool {
	return getBoolEnvVar(antreaCloudEKSEnvKey, false)
}
