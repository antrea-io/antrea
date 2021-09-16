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
	"runtime"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

const (
	NodeNameEnvKey        = "NODE_NAME"
	podNameEnvKey         = "POD_NAME"
	podNamespaceEnvKey    = "POD_NAMESPACE"
	svcAcctNameEnvKey     = "SERVICEACCOUNT_NAME"
	antreaConfigMapEnvKey = "ANTREA_CONFIG_MAP_NAME"

	antreaCloudEKSEnvKey = "ANTREA_CLOUD_EKS"

	defaultAntreaNamespace = "kube-system"

	allowNoEncapWithoutAntreaProxyEnvKey = "ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY"
)

// GetNodeName returns the node's name used in Kubernetes, based on the priority:
// - Environment variable NODE_NAME, which should be set by Downward API
// - OS's hostname
func GetNodeName() (string, error) {
	nodeName := os.Getenv(NodeNameEnvKey)
	if nodeName != "" {
		return nodeName, nil
	}
	klog.Infof("Environment variable %s not found, using hostname instead", NodeNameEnvKey)
	var err error
	nodeName, err = os.Hostname()
	if err != nil {
		klog.Errorf("Failed to get local hostname: %v", err)
		return "", err
	}
	if runtime.GOOS == "windows" {
		return strings.ToLower(nodeName), nil
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

// GetAntreaConfigMapName returns the configMap name of Antrea config.
func GetAntreaConfigMapName() string {
	configMapName := os.Getenv(antreaConfigMapEnvKey)
	if configMapName == "" {
		klog.Warningf("Environment variable %s not found", antreaConfigMapEnvKey)
	}
	return configMapName
}

// GetPodNamespace returns Namespace of the Pod where the code executes.
func GetPodNamespace() string {
	podNamespace := os.Getenv(podNamespaceEnvKey)
	if podNamespace == "" {
		klog.Warningf("Environment variable %s not found", podNamespaceEnvKey)
	}
	return podNamespace
}

// GetAntreaControllerServiceAccountName returns the ServiceAccount name associated with antrea-controller.
func GetAntreaControllerServiceAccount() string {
	svcAcctName := os.Getenv(svcAcctNameEnvKey)
	if svcAcctName == "" {
		// default value set for antrea-controller
		svcAcctName = "antrea-controller"
	}
	return svcAcctName
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

// IsCloudEKS returns true if Antrea is used to enforce NetworkPolicies in an EKS cluster.
func IsCloudEKS() bool {
	return getBoolEnvVar(antreaCloudEKSEnvKey, false)
}

// GetAntreaNamespace tries to determine the Namespace in which Antrea is running by looking at the
// POD_NAMESPACE environment variable. If this environment variable is not set (e.g. because the
// Antrea component is not run as a Pod), "kube-system" is returned.
func GetAntreaNamespace() string {
	namespace := GetPodNamespace()
	if namespace == "" {
		klog.Warningf("Failed to get Pod Namespace from environment. Using \"%s\" as the Antrea Service Namespace", defaultAntreaNamespace)
		namespace = defaultAntreaNamespace
	}
	return namespace
}

// GetAllowNoEncapWithoutAntreaProxy returns whether AntreaProxy can be disabled for traffic
// modes which support noEncap.
func GetAllowNoEncapWithoutAntreaProxy() bool {
	return getBoolEnvVar(allowNoEncapWithoutAntreaProxyEnvKey, false)
}
