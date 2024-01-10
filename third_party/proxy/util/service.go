/*
Copyright 2016 The Kubernetes Authors.

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
- Remove consts: "defaultLoadBalancerSourceRanges"
- Remove functions: "IsAllowAll", "GetLoadBalancerSourceRanges", "GetServiceHealthCheckPathPort"
*/

package util

import v1 "k8s.io/api/core/v1"

func ExternallyAccessible(service *v1.Service) bool {
	return service.Spec.Type == v1.ServiceTypeLoadBalancer ||
		service.Spec.Type == v1.ServiceTypeNodePort ||
		(service.Spec.Type == v1.ServiceTypeClusterIP && len(service.Spec.ExternalIPs) > 0)
}

// ExternalPolicyLocal checks if service has ETP = Local.
func ExternalPolicyLocal(service *v1.Service) bool {
	if !ExternallyAccessible(service) {
		return false
	}
	return service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal
}

// InternalPolicyLocal checks if service has ITP = Local.
func InternalPolicyLocal(service *v1.Service) bool {
	if service.Spec.InternalTrafficPolicy == nil {
		return false
	}
	return *service.Spec.InternalTrafficPolicy == v1.ServiceInternalTrafficPolicyLocal
}

// NeedsHealthCheck checks if service needs health check.
func NeedsHealthCheck(service *v1.Service) bool {
	if service.Spec.Type != v1.ServiceTypeLoadBalancer {
		return false
	}
	return ExternalPolicyLocal(service)
}
