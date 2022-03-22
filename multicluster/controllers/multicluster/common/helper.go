/*
Copyright 2021 Antrea Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import corev1 "k8s.io/api/core/v1"

const (
	AntreaMCServiceAnnotation   = "multicluster.antrea.io/imported-service"
	AntreaMCACNPAnnotation      = "multicluster.antrea.io/imported-acnp"
	AntreaMCClusterIDAnnotation = "multicluster.antrea.io/local-cluster-id"

	AntreaMCSPrefix                = "antrea-mc-"
	ServiceKind                    = "Service"
	EndpointsKind                  = "Endpoints"
	AntreaClusterNetworkPolicyKind = "AntreaClusterNetworkPolicy"
	ServiceImportKind              = "ServiceImport"

	SourceName      = "sourceName"
	SourceNamespace = "sourceNamespace"
	SourceClusterID = "sourceClusterID"
	SourceKind      = "sourceKind"

	DefaultWorkerCount = 5

	ResourceExportFinalizer = "resourceexport.finalizers.antrea.io"
)

// TODO: Use NamespacedName stringer method instead of this. e.g. nsName.String()
func NamespacedName(namespace, name string) string {
	return namespace + "/" + name
}

func StringExistsInSlice(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func RemoveStringFromSlice(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

// FilterEndpointSubsets keeps IPs only and removes others which are unnecessary information for other member clusters.
func FilterEndpointSubsets(subsets []corev1.EndpointSubset) []corev1.EndpointSubset {
	newSubsets := []corev1.EndpointSubset{}
	for _, s := range subsets {
		subset := corev1.EndpointSubset{}
		newAddresses := []corev1.EndpointAddress{}
		for _, addr := range s.Addresses {
			newAddresses = append(newAddresses, corev1.EndpointAddress{
				IP: addr.IP,
			})
		}
		if len(newAddresses) > 0 {
			subset.Addresses = newAddresses
			subset.Ports = s.Ports
			newSubsets = append(newSubsets, subset)
		}
	}
	return newSubsets
}
