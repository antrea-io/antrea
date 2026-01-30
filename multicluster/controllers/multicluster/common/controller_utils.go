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
	"net"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha2 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha2"
)

var createDiscoveryClientFn = createDiscoveryClient

// discoverServiceCIDRByInvalidServiceCreation creates an invalid Service to get returned error, and analyzes
// the error message to get Service CIDR.
// TODO: add dual-stack support.
func discoverServiceCIDRByInvalidServiceCreation(ctx context.Context, k8sClient client.Client, namespace string) (string, error) {
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

func isK8sVersionGreaterThanOrEqualTo(discoveryClient discovery.DiscoveryInterface, expectedVersion string) (bool, error) {
	versionInfo, err := discoveryClient.ServerVersion()
	if err != nil {
		return false, err
	}
	vers, err := version.ParseGeneric(versionInfo.GitVersion)
	if err != nil {
		return false, err
	}
	return vers.AtLeast(version.MustParseGeneric(expectedVersion)), nil
}

func getClusterServiceCIDR(ctx context.Context, apiReader client.Reader) (string, error) {
	// A ServiceCIDR CR named 'kubernetes' will be created by default since v1.33.0.
	// We will retrieve it to get the Service CIDR.
	var svcCIDR networkingv1.ServiceCIDR
	err := apiReader.Get(ctx, types.NamespacedName{Name: "kubernetes"}, &svcCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to get ServiceCIDR 'kubernetes': %w", err)
	}

	for _, cidr := range svcCIDR.Spec.CIDRs {
		if isIPv4CIDR(cidr) {
			return cidr, nil
		}
	}
	return "", fmt.Errorf("IPv4 Service CIDR not found")
}

func createDiscoveryClient(config *rest.Config) (discovery.DiscoveryInterface, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	return discoveryClient, nil
}

func DiscoverClusterServiceCIDR(ctx context.Context, mgrConfig *rest.Config, apiReader client.Reader, client client.Client, namespace string) (string, error) {
	var versionMatched bool
	var cidr string
	discoveryClient, err := createDiscoveryClientFn(mgrConfig)
	if err != nil {
		return "", err
	}
	versionMatched, err = isK8sVersionGreaterThanOrEqualTo(discoveryClient, "v1.33.0")
	if versionMatched {
		cidr, err = getClusterServiceCIDR(ctx, apiReader)
		if err != nil {
			return "", err
		}
	}

	if !versionMatched || err != nil {
		klog.InfoS("Falling back to legacy Service CIDR detection", "error", err)
		cidr, err = discoverServiceCIDRByInvalidServiceCreation(context.TODO(), client, namespace)
		if err != nil {
			return "", err
		}
	}
	return cidr, nil
}

func isIPv4CIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	return err == nil && ip.To4() != nil
}

func NewClusterInfoResourceExportName(clusterID string) string {
	return clusterID + "-clusterinfo"
}

func getClusterIDFromClusterClaim(c client.Client, clusterSet *mcv1alpha2.ClusterSet) (ClusterID, error) {
	configNamespace := clusterSet.GetNamespace()

	clusterClaimList := &mcv1alpha2.ClusterClaimList{}
	if err := c.List(context.TODO(), clusterClaimList, client.InNamespace(configNamespace)); err != nil {
		return "", err
	}
	if len(clusterClaimList.Items) == 0 {
		return "", fmt.Errorf("ClusterClaim is not configured for the cluster")
	}

	for _, clusterClaim := range clusterClaimList.Items {
		if clusterClaim.Name == mcv1alpha2.WellKnownClusterClaimID {
			return ClusterID(clusterClaim.Value), nil
		}
	}

	return "", fmt.Errorf("ClusterClaim not configured for Name=%s",
		mcv1alpha2.WellKnownClusterClaimID)
}

func GetClusterID(clusterCalimCRDAvailable bool, req ctrl.Request, client client.Client, clusterSet *mcv1alpha2.ClusterSet) (ClusterID, error) {
	if clusterSet.Spec.ClusterID == "" {
		// ClusterID is a required field, and the empty value case should only happen
		// when Antrea Multi-cluster is upgraded from an old version prior to v1.13.
		// Here we try to get the ClusterID from ClusterClaim before returning any error.
		if clusterCalimCRDAvailable {
			clusterID, err := getClusterIDFromClusterClaim(client, clusterSet)
			if err == nil {
				return clusterID, nil
			}
		}
		return "", fmt.Errorf("'clusterID' is not set in the ClusterSet %s spec", req.NamespacedName)
	}
	return ClusterID(clusterSet.Spec.ClusterID), nil
}
