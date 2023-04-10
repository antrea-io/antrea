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
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterproperties,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterproperties/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterproperties/finalizers,verbs=update

func ValidateLocalClusterProperty(c client.Client, clusterSet *multiclusterv1alpha1.ClusterSet) (clusterID ClusterID, clusterSetID ClusterSetID, err error) {
	configNamespace := clusterSet.GetNamespace()

	clusterPropertyList := &multiclusterv1alpha1.ClusterPropertyList{}
	klog.InfoS("Validating ClusterProperty", "namespace", configNamespace)
	if err = c.List(context.TODO(), clusterPropertyList, client.InNamespace(configNamespace)); err != nil {
		return
	}
	if len(clusterPropertyList.Items) == 0 {
		err = fmt.Errorf("ClusterProperty is not configured for the cluster")
		return
	}

	wellKnownClusterSetPropertyIDExist := false
	wellKnownClusterPropertyIDExist := false
	for _, clusterProperty := range clusterPropertyList.Items {
		klog.InfoS("Processing ClusterProperty", "name", clusterProperty.Name, "value", clusterProperty.Value)
		if clusterProperty.Name == multiclusterv1alpha1.WellKnownClusterPropertyClusterSet {
			wellKnownClusterSetPropertyIDExist = true
			clusterSetID = ClusterSetID(clusterProperty.Value)
		} else if clusterProperty.Name == multiclusterv1alpha1.WellKnownClusterPropertyID {
			wellKnownClusterPropertyIDExist = true
			clusterID = ClusterID(clusterProperty.Value)
		}
	}

	if !wellKnownClusterSetPropertyIDExist {
		err = fmt.Errorf("ClusterProperty not configured for Name=%s",
			multiclusterv1alpha1.WellKnownClusterPropertyClusterSet)
		return
	}

	if !wellKnownClusterPropertyIDExist {
		err = fmt.Errorf("ClusterProperty not configured for Name=%s",
			multiclusterv1alpha1.WellKnownClusterPropertyID)
		return
	}

	if clusterSet.Name != string(clusterSetID) {
		err = fmt.Errorf("ClusterSet Name=%s is not same as ClusterProperty Value=%s for Name=%s",
			clusterSet.Name, clusterSetID, multiclusterv1alpha1.WellKnownClusterPropertyClusterSet)
		return
	}

	return
}

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
