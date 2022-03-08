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

package networkpolicy

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{
		Message: fmt.Sprintf(msg, params...),
		Status:  metav1.StatusFailure,
	}
}

func ConvertClusterGroupCRD(Object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	klog.V(2).Infof("Converting CRD for ClusterGroup %s", Object.GetName())
	convertedObject := Object.DeepCopy()
	fromVersion := Object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}
	switch Object.GetAPIVersion() {
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha3":
			ipb, found, err := unstructured.NestedMap(convertedObject.Object, "spec", "ipBlock")
			if err == nil && found && len(ipb) > 0 {
				unstructured.RemoveNestedField(convertedObject.Object, "spec", "ipBlock")
				// unstructured.SetNestedSlice expects a slice of interface as value
				ipBlocks := make([]interface{}, 1)
				ipBlocks[0] = ipb
				unstructured.SetNestedSlice(convertedObject.Object, ipBlocks, "spec", "ipBlocks")
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	case "crd.antrea.io/v1alpha3":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			return convertedObject, metav1.Status{
				Status: metav1.StatusSuccess,
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion version %q", fromVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}

func translateV1A1NetworkPolicyPortToV1A2PeerProtocol(ports []interface{}) (protocols []interface{}) {
	for _, eachPort := range ports {
		mapPort := eachPort.(map[string]interface{})
		protocol, _, _ := unstructured.NestedString(mapPort, "protocol")
		if protocol == "" {
			protocol = "TCP"
		}

		l4Protocol := make(map[string]interface{})
		port, found, err := unstructured.NestedFieldNoCopy(mapPort, "port")
		if err == nil && found && port != nil {
			unstructured.SetNestedField(l4Protocol, port, "port")
		}
		endPort, found, err := unstructured.NestedFieldNoCopy(mapPort, "endPort")
		if err == nil && found && endPort != nil {
			unstructured.SetNestedField(l4Protocol, endPort, "endPort")
		}

		peerProtocol := make(map[string]interface{}, 1)
		unstructured.SetNestedMap(peerProtocol, l4Protocol, strings.ToLower(protocol))
		protocols = append(protocols, peerProtocol)
	}
	return
}

func convertV1A1RuleToV1A2Rule(rules []interface{}) {
	for _, rule := range rules {
		mapRule := rule.(map[string]interface{})
		ports, found, err := unstructured.NestedSlice(mapRule, "ports")
		if err == nil && found && len(ports) > 0 {
			protocols := translateV1A1NetworkPolicyPortToV1A2PeerProtocol(ports)
			unstructured.RemoveNestedField(mapRule, "ports")
			unstructured.SetNestedSlice(mapRule, protocols, "protocols")
		}
	}
}

func ConvertClusterNetworkPolicyCRD(Object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	klog.V(2).Infof("Converting CRD for ClusterNetworkPolicy %s", Object.GetName())
	convertedObject := Object.DeepCopy()
	fromVersion := Object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}
	switch Object.GetAPIVersion() {
	case "crd.antrea.io/v1alpha1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			ingressRules, found, err := unstructured.NestedFieldNoCopy(convertedObject.Object, "spec", "ingress")
			if err == nil && found {
				if ingressRulesSlice, ok := ingressRules.([]interface{}); ok {
					convertV1A1RuleToV1A2Rule(ingressRulesSlice)
				}
			}
			egressRules, found, err := unstructured.NestedFieldNoCopy(convertedObject.Object, "spec", "egress")
			if err == nil && found {
				if egressRulesSlice, ok := egressRules.([]interface{}); ok {
					convertV1A1RuleToV1A2Rule(egressRulesSlice)
				}
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha1":
			return convertedObject, metav1.Status{
				Status: metav1.StatusSuccess,
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion version %q", fromVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}

func ConvertNetworkPolicyCRD(Object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	klog.V(2).Infof("Converting CRD for NetworkPolicy %s", Object.GetName())
	convertedObject := Object.DeepCopy()
	fromVersion := Object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}
	switch Object.GetAPIVersion() {
	case "crd.antrea.io/v1alpha1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			ingressRules, found, err := unstructured.NestedSlice(convertedObject.Object, "spec", "ingress")
			if err == nil && found && len(ingressRules) > 0 {
				convertV1A1RuleToV1A2Rule(ingressRules)
			}
			egressRules, found, err := unstructured.NestedSlice(convertedObject.Object, "spec", "egress")
			if err == nil && found && len(egressRules) > 0 {
				convertV1A1RuleToV1A2Rule(egressRules)
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha1":
			return convertedObject, metav1.Status{
				Status: metav1.StatusSuccess,
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion version %q", fromVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}

func ConvertExternalEntityCRD(Object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	return nil, metav1.Status{
		Status: metav1.StatusFailure,
	}
}
