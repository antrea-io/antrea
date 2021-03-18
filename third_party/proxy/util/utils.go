/*
Copyright 2017 The Kubernetes Authors.

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
/*
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

Modifies:
- Remove imports: "errors", "strconv", "k8s.io/apimachinery/pkg/util/rand",
  "k8s.io/apimachinery/pkg/util/sets", "k8s.io/kubernetes/pkg/apis/core/v1/helper"
- Remove consts: "IPv4ZeroCIDR", "IPv6ZeroCIDR"
- Remove vars: "ErrAddressNotAllowed", "ErrNoAddresses"
- Remove functions: "isValidEndpoint", "BuildPortsToEndpointsMap", "IsZeroCIDR",
  "IsProxyableIP", "isProxyableIP", "IsProxyableHostname", "IsLocalIP", "GetNodeAddresses".
*/
package util

import (
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	utilnet "k8s.io/utils/net"

	"k8s.io/klog/v2"
)

// Resolver is an interface for net.Resolver
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ShouldSkipService checks if a given service should skip proxying
func ShouldSkipService(svcName types.NamespacedName, service *v1.Service) bool {
	// if ClusterIP is "None" or empty, skip proxying
	if service.Spec.ClusterIP == v1.ClusterIPNone || service.Spec.ClusterIP == "" {
		klog.V(3).Infof("Skipping service %s due to clusterIP = %q", svcName, service.Spec.ClusterIP)
		return true
	}
	// Even if ClusterIP is set, ServiceTypeExternalName services don't get proxied
	if service.Spec.Type == v1.ServiceTypeExternalName {
		klog.V(3).Infof("Skipping service %s due to Type=ExternalName", svcName)
		return true
	}
	return false
}

// LogAndEmitIncorrectIPVersionEvent logs and emits incorrect IP version event.
func LogAndEmitIncorrectIPVersionEvent(recorder record.EventRecorder, fieldName, fieldValue, svcNamespace, svcName string, svcUID types.UID) {
	errMsg := fmt.Sprintf("%s in %s has incorrect IP version", fieldValue, fieldName)
	klog.Errorf("%s (service %s/%s).", errMsg, svcNamespace, svcName)
	if recorder != nil {
		recorder.Eventf(
			&v1.ObjectReference{
				Kind:      "Service",
				Name:      svcName,
				Namespace: svcNamespace,
				UID:       svcUID,
			}, v1.EventTypeWarning, "KubeProxyIncorrectIPVersion", errMsg)
	}
}

// FilterIncorrectIPVersion filters out the incorrect IP version case from a slice of IP strings.
func FilterIncorrectIPVersion(ipStrings []string, isIPv6Mode bool) ([]string, []string) {
	return filterWithCondition(ipStrings, isIPv6Mode, utilnet.IsIPv6String)
}

// FilterIncorrectCIDRVersion filters out the incorrect IP version case from a slice of CIDR strings.
func FilterIncorrectCIDRVersion(ipStrings []string, isIPv6Mode bool) ([]string, []string) {
	return filterWithCondition(ipStrings, isIPv6Mode, utilnet.IsIPv6CIDRString)
}

func filterWithCondition(strs []string, expectedCondition bool, conditionFunc func(string) bool) ([]string, []string) {
	var corrects, incorrects []string
	for _, str := range strs {
		if conditionFunc(str) != expectedCondition {
			incorrects = append(incorrects, str)
		} else {
			corrects = append(corrects, str)
		}
	}
	return corrects, incorrects
}
