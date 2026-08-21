// Copyright 2026 Antrea Authors
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

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/features"
)

// frrPath is one BGP path for a prefix as reported by the remote FRR router.
type frrPath struct {
	// Nexthop is the address of the Node which advertised the path.
	Nexthop string
	// MED is the MULTI_EXIT_DISC attribute of the path, 0 when the attribute is absent, which is how
	// FRR itself compares a path without a MED.
	MED uint32
	// Best reports whether FRR selected this path as the best one for the prefix.
	Best bool
}

// dumpFRRRouterBGPPaths returns every BGP path known to the remote FRR router, keyed by prefix.
// Unlike dumpFRRRouterBGPRoutes, which reads the routing table and therefore only sees the selected
// paths, this reads the BGP table so that the backup paths and their attributes are visible too.
func dumpFRRRouterBGPPaths() (map[string][]frrPath, error) {
	rc, stdout, stderr, err := runVtyshCommands([]string{"show bgp ipv4 unicast json"})
	if err != nil || rc != 0 {
		log.Println(stderr)
		return nil, fmt.Errorf("error when running command to show the BGP table: %v, rc: %d", err, rc)
	}
	// Only the fields the test needs are declared. FRR reports the MED as "metric"; "med" is
	// accepted as well so that the test keeps working if the field is ever renamed.
	var parsed struct {
		Routes map[string][]struct {
			Metric   *uint32 `json:"metric"`
			MED      *uint32 `json:"med"`
			Bestpath *struct {
				Overall bool `json:"overall"`
			} `json:"bestpath"`
			Nexthops []struct {
				IP string `json:"ip"`
			} `json:"nexthops"`
		} `json:"routes"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		return nil, fmt.Errorf("error when parsing the BGP table: %w", err)
	}
	paths := make(map[string][]frrPath, len(parsed.Routes))
	for prefix, entries := range parsed.Routes {
		for _, entry := range entries {
			path := frrPath{Best: entry.Bestpath != nil && entry.Bestpath.Overall}
			if entry.Metric != nil {
				path.MED = *entry.Metric
			} else if entry.MED != nil {
				path.MED = *entry.MED
			}
			if len(entry.Nexthops) > 0 {
				path.Nexthop = entry.Nexthops[0].IP
			}
			paths[prefix] = append(paths[prefix], path)
		}
	}
	return paths, nil
}

// checkFRRRouterBGPPaths polls the BGP table of the remote FRR router until the paths for prefix
// satisfy the given condition.
func checkFRRRouterBGPPaths(t *testing.T, prefix string, timeout time.Duration, condition func([]frrPath) bool) []frrPath {
	t.Helper()
	var got []frrPath
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, true, func(context.Context) (bool, error) {
		paths, err := dumpFRRRouterBGPPaths()
		if err != nil {
			return false, nil
		}
		got = paths[prefix]
		return condition(got), nil
	})
	require.NoError(t, err, "The BGP paths for %s never matched the expectation, got: %+v", prefix, got)
	return got
}

// TestBGPPolicyServiceMED verifies that the MULTI_EXIT_DISC attribute configured in a BGPPolicy
// reaches the remote BGP peer, in both the Static and the NodePriority modes.
func TestBGPPolicyServiceMED(t *testing.T) {
	skipIfFeatureDisabled(t, features.BGPPolicy, true, false)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)
	skipIfExternalFRRNotSet(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")
	defer teardownTest(t, data)

	t.Log("Updating the specific Secret storing the passwords of BGP peers")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kubeNamespace,
			Name:      agenttypes.BGPPolicySecretName,
		},
		Data: map[string][]byte{
			fmt.Sprintf("%s-%d", externalInfo.externalFRRIPv4, int32(65000)): []byte(bgpPeerPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(kubeNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(kubeNamespace).Delete(context.TODO(), agenttypes.BGPPolicySecretName, metav1.DeleteOptions{})

	// No backend Pod is needed: both Services use the default `externalTrafficPolicy: Cluster`, so
	// their IPs are advertised regardless of where the Endpoints are.
	configureExternalBGPRouter(t, int32(65000), int32(64512), true)

	createBGPPolicy := func(t *testing.T, ipTypes []crdv1alpha1.ServiceIPType, med *crdv1alpha1.MEDAdvertisement) {
		t.Helper()
		bgpPolicy := &crdv1alpha1.BGPPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-med-policy"},
			Spec: crdv1alpha1.BGPPolicySpec{
				NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{}},
				LocalASN:     int32(64512),
				ListenPort:   ptr.To[int32](179),
				Advertisements: crdv1alpha1.Advertisements{
					Service: &crdv1alpha1.ServiceAdvertisement{IPTypes: ipTypes, MED: med},
				},
				BGPPeers: []crdv1alpha1.BGPPeer{
					{Address: externalInfo.externalFRRIPv4, ASN: int32(65000)},
				},
			},
		}
		_, err := data.CRDClient.CrdV1alpha1().BGPPolicies().Create(context.TODO(), bgpPolicy, metav1.CreateOptions{})
		require.NoError(t, err)
		t.Cleanup(func() {
			data.CRDClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), bgpPolicy.Name, metav1.DeleteOptions{})
		})
	}

	t.Run("Static mode applies the same MED on every Node", func(t *testing.T) {
		svc, err := data.createAgnhostClusterIPService("agnhost-med-static", false, ptr.To(corev1.IPv4Protocol))
		require.NoError(t, err)
		defer data.deleteService(svc.Namespace, svc.Name)
		prefix := svc.Spec.ClusterIP + "/32"

		createBGPPolicy(t, []crdv1alpha1.ServiceIPType{crdv1alpha1.ServiceIPTypeClusterIP}, &crdv1alpha1.MEDAdvertisement{
			Mode:      crdv1alpha1.MEDModeStatic,
			BaseValue: ptr.To[int64](500),
		})

		paths := checkFRRRouterBGPPaths(t, prefix, 60*time.Second, func(paths []frrPath) bool {
			if len(paths) != len(clusterInfo.nodes) {
				return false
			}
			for _, p := range paths {
				if p.MED != 500 {
					return false
				}
			}
			return true
		})
		t.Logf("Every Node advertised %s with MED 500: %+v", prefix, paths)
	})

	t.Run("NodePriority mode ranks the Nodes of the ExternalIPPool", func(t *testing.T) {
		skipIfFeatureDisabled(t, features.ServiceExternalIP, true, false)

		ipRange := v1beta1.IPRange{CIDR: "172.31.10.0/28"}
		pool := data.createExternalIPPool(t, "bgp-med-pool-", ipRange, nil, nil, nil)
		defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

		svc, err := data.createAgnhostLoadBalancerService("agnhost-med-priority", false, false, nil, ptr.To(corev1.IPv4Protocol),
			map[string]string{agenttypes.ServiceExternalIPPoolAnnotationKey: pool.Name})
		require.NoError(t, err)
		defer data.deleteService(svc.Namespace, svc.Name)

		// The external IP is allocated asynchronously by antrea-controller.
		var externalIP string
		require.NoError(t, wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			svc, err := data.clientset.CoreV1().Services(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil || len(svc.Status.LoadBalancer.Ingress) == 0 {
				return false, nil
			}
			externalIP = svc.Status.LoadBalancer.Ingress[0].IP
			return externalIP != "", nil
		}), "The Service never got an external IP from the ExternalIPPool")
		prefix := externalIP + "/32"

		const base, step = int64(100), int64(100)
		createBGPPolicy(t, []crdv1alpha1.ServiceIPType{crdv1alpha1.ServiceIPTypeLoadBalancerIP}, &crdv1alpha1.MEDAdvertisement{
			Mode:      crdv1alpha1.MEDModeNodePriority,
			BaseValue: ptr.To(base),
			Step:      ptr.To(step),
		})

		numNodes := len(clusterInfo.nodes)
		paths := checkFRRRouterBGPPaths(t, prefix, 60*time.Second, func(paths []frrPath) bool {
			return len(paths) == numNodes
		})

		// Every Node must advertise the IP with a distinct MED taken from the expected ladder, and
		// the path with the base value must be the one FRR selects.
		var meds []uint32
		var bestMED uint32
		for _, p := range paths {
			meds = append(meds, p.MED)
			if p.Best {
				bestMED = p.MED
			}
		}
		slices.Sort(meds)
		var expectedMEDs []uint32
		for i := 0; i < numNodes; i++ {
			expectedMEDs = append(expectedMEDs, uint32(base+int64(i)*step))
		}
		assert.Equal(t, expectedMEDs, meds, "Each Node must advertise %s with a distinct MED, got: %+v", prefix, paths)
		assert.Equal(t, uint32(base), bestMED, "The most preferred path must be the one with the base MED, got: %+v", paths)
	})
}
