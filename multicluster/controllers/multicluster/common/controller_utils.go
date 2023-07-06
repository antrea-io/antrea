// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"context"
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DiscoverServiceCIDRByInvalidServiceCreation creates an invalid Service to get returned error, and analyzes
// the error message to get Service CIDR.
// TODO: add dual-stack support.
func DiscoverServiceCIDRByInvalidServiceCreation(ctx context.Context, k8sClient client.Client, namespace string) (string, error) {
	invalidSvcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-svc",
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "0.0.0.0",
			Ports: []corev1.ServicePort{
				{
					Port: 443,
					TargetPort: intstr.IntOrString{
						IntVal: 443,
					},
				},
			},
		},
	}

	err := k8sClient.Create(ctx, invalidSvcSpec, &client.CreateOptions{})
	// Creating invalid Service didn't fail as expected
	if err == nil {
		return "", fmt.Errorf("could not determine the Service ClusterIP range via Service creation - " +
			"expected a specific error but none was returned")
	}

	return parseServiceCIDRFromError(err.Error())
}

// TODO: add dual-stack support.
func parseServiceCIDRFromError(msg string) (string, error) {
	// Expected error message is like below:
	// `The Service "invalid-svc" is invalid: spec.clusterIPs: Invalid value: []string{"0.0.0.0"}:
	// failed to allocate IP 0.0.0.0: provided IP is not in the valid range. The range of valid IPs is 10.19.0.0/18`
	// The CIDR string should be parsed from the error message is:
	//   10.19.0.0/18
	re := regexp.MustCompile(".*valid IPs is (.*)$")

	match := re.FindStringSubmatch(msg)
	if match == nil {
		return "", fmt.Errorf("could not determine the ClusterIP range via Service creation - the expected error "+
			"was not returned. The actual error was %q", msg)
	}

	return match[1], nil
}

func NewClusterInfoResourceExportName(clusterID string) string {
	return clusterID + "-clusterinfo"
}
