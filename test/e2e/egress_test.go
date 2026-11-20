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

package e2e

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/v2/pkg/agent/config"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/features"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const waitEgressRealizedTimeout = 3 * time.Second

func skipIfEgressDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.Egress, true, true)
}

func skipIfEgressSeparateSubnetDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.EgressSeparateSubnet, true, false)
}

func TestEgress(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfAntreaIPAMTest(t)
	skipIfEgressDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	// Egress works for encap and hybrid modes.
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNoEncap)
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNetworkPolicyOnly)

	t.Run("testEgressClientIP", func(t *testing.T) { testEgressClientIP(t, data) })
	t.Run("testEgressClientIPFromVLANSubnet", func(t *testing.T) { testEgressClientIPFromVLANSubnet(t, data) })
	t.Run("testEgressCRUD", func(t *testing.T) { testEgressCRUD(t, data) })
	t.Run("testExternalIPPoolVersionConversion", func(t *testing.T) { testExternalIPPoolVersionConversion(t, data) })
	t.Run("testEgressConditionsVersionConversion", func(t *testing.T) { testEgressConditionsVersionConversion(t, data) })
	t.Run("testEgressLegacyClientCompatibility", func(t *testing.T) { testEgressLegacyClientCompatibility(t, data) })
	t.Run("testEgressIPFamilySelection", func(t *testing.T) { testEgressIPFamilySelection(t, data) })
	t.Run("testEgressUpdateEgressIP", func(t *testing.T) { testEgressUpdateEgressIP(t, data) })
	t.Run("testEgressUpdateNodeSelector", func(t *testing.T) { testEgressUpdateNodeSelector(t, data) })
	t.Run("testEgressNodeFailure", func(t *testing.T) { testEgressNodeFailure(t, data) })
	t.Run("testCreateExternalIPPool", func(t *testing.T) { testCreateExternalIPPool(t, data) })
	t.Run("testUpdateBandwidth", func(t *testing.T) { testEgressUpdateBandwidth(t, data) })
}

func testCreateExternalIPPool(t *testing.T, data *TestData) {
	eip := v1beta2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool"},
		Spec:       v1beta2.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro-"}}},
	}

	_, err := data.CRDClient.CrdV1beta2().ExternalIPPools().Create(context.TODO(), &eip, metav1.CreateOptions{})
	assert.Error(t, err, "Should fail to create ExternalIPPool")
}

func testExternalIPPoolVersionConversion(t *testing.T, data *TestData) {
	ctx := context.Background()
	v1Pools := data.CRDClient.CrdV1beta1().ExternalIPPools()
	v2Pools := data.CRDClient.CrdV1beta2().ExternalIPPools()
	for _, tc := range []struct {
		name   string
		ranges []crdv1beta1.IPRange
		subnet *crdv1beta1.SubnetInfo
	}{
		{name: "native IPv4", ranges: []crdv1beta1.IPRange{{CIDR: "198.18.10.0/24"}},
			subnet: &crdv1beta1.SubnetInfo{Gateway: "198.18.10.1", PrefixLength: 24, VLAN: 10}},
		{name: "native IPv6", ranges: []crdv1beta1.IPRange{{CIDR: "2001:db8:10::/64"}},
			subnet: &crdv1beta1.SubnetInfo{Gateway: "2001:db8:10::1", PrefixLength: 64, VLAN: 20}},
		{name: "empty pool", ranges: []crdv1beta1.IPRange{},
			subnet: &crdv1beta1.SubnetInfo{Gateway: "198.18.10.1", PrefixLength: 24, VLAN: 10}},
		{name: "no subnet", ranges: []crdv1beta1.IPRange{{CIDR: "198.18.10.0/24"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, err := v1Pools.Create(ctx, &crdv1beta1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "conversion-native-"},
				Spec:       crdv1beta1.ExternalIPPoolSpec{IPRanges: tc.ranges, SubnetInfo: tc.subnet},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, v1Pools.Delete(ctx, old.Name, metav1.DeleteOptions{})) })
			var expected []v1beta2.SubnetInfo
			if tc.subnet != nil {
				expected = []v1beta2.SubnetInfo{{Gateway: tc.subnet.Gateway, PrefixLength: tc.subnet.PrefixLength, VLAN: tc.subnet.VLAN}}
			}
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current, err := v2Pools.Get(ctx, old.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				assert.Equal(t, expected, current.Spec.Subnets)
				current.Labels = map[string]string{"conversion": "v2-update"}
				_, err = v2Pools.Update(ctx, current, metav1.UpdateOptions{})
				return err
			}))
			back, err := v1Pools.Get(ctx, old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tc.subnet, back.Spec.SubnetInfo)
			assert.Equal(t, "v2-update", back.Labels["conversion"])
		})
	}

	t.Run("dual-stack old client updates", func(t *testing.T) {
		expected := []v1beta2.SubnetInfo{
			{Gateway: "2001:db8:10::1", PrefixLength: 64, VLAN: 20},
			{Gateway: "198.18.10.1", PrefixLength: 24, VLAN: 10},
		}
		created, err := v2Pools.Create(ctx, &v1beta2.ExternalIPPool{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "conversion-dual-"},
			Spec: v1beta2.ExternalIPPoolSpec{
				IPRanges: []v1beta2.IPRange{{CIDR: "198.18.10.0/24"}, {CIDR: "2001:db8:10::/64"}},
				Subnets:  expected,
			},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, v2Pools.Delete(ctx, created.Name, metav1.DeleteOptions{})) })
		assert.Equal(t, expected, created.Spec.Subnets)
		for _, edit := range []string{"label", "gateway and VLAN", "remove subnet"} {
			t.Run(edit, func(t *testing.T) {
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					old, err := v1Pools.Get(ctx, created.Name, metav1.GetOptions{})
					if err != nil {
						return err
					}
					require.NotNil(t, old.Spec.SubnetInfo)
					assert.Equal(t, expected[1].Gateway, old.Spec.SubnetInfo.Gateway)
					switch edit {
					case "label":
						old.Labels = map[string]string{"conversion": "old-client"}
					case "gateway and VLAN":
						old.Spec.SubnetInfo.Gateway = "198.18.10.2"
						old.Spec.SubnetInfo.VLAN = 30
					case "remove subnet":
						old.Spec.SubnetInfo = nil
					}
					_, err = v1Pools.Update(ctx, old, metav1.UpdateOptions{})
					return err
				})
				if edit == "remove subnet" {
					require.ErrorContains(t, err, "v1beta1 clients cannot remove subnets from a dual-stack ExternalIPPool")
				} else {
					require.NoError(t, err)
				}
				if edit == "gateway and VLAN" {
					expected[1].Gateway = "198.18.10.2"
					expected[1].VLAN = 30
				}
				current, err := v2Pools.Get(ctx, created.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, expected, current.Spec.Subnets)
			})
		}
	})
}

func testEgressConditionsVersionConversion(t *testing.T, data *TestData) {
	egress, err := data.CRDClient.CrdV1beta1().Egresses().Create(context.TODO(), &crdv1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "conditions-conversion-"},
		Spec: crdv1beta1.EgressSpec{
			EgressIP: "192.0.2.240",
			AppliedTo: crdv1beta1.AppliedTo{PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"conditions-conversion": "unused"},
			}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
	updateLegacyStatus := func(update func(*crdv1beta1.EgressStatus)) {
		t.Helper()
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current, err := data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			update(&current.Status)
			_, err = data.CRDClient.CrdV1beta1().Egresses().UpdateStatus(context.TODO(), current, metav1.UpdateOptions{})
			return err
		})
		require.NoError(t, err)
	}
	// Old clients may omit fields which the standard v1beta2 condition requires.
	updateLegacyStatus(func(status *crdv1beta1.EgressStatus) {
		status.Conditions = []crdv1beta1.EgressCondition{{Type: "Ready", Status: v1.ConditionTrue}}
	})
	converted, err := data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	condition := meta.FindStatusCondition(converted.Status.Conditions, "Ready")
	require.NotNil(t, condition)
	assert.Equal(t, "Unknown", condition.Reason)
	assert.Empty(t, condition.Message)
	assert.True(t, converted.CreationTimestamp.Equal(&condition.LastTransitionTime))
	assert.Zero(t, condition.ObservedGeneration)
	// Exercise API-server validation and storage pruning, not just the conversion functions.
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		meta.FindStatusCondition(current.Status.Conditions, "Ready").ObservedGeneration = current.Generation
		_, err = data.CRDClient.CrdV1beta2().Egresses().UpdateStatus(context.TODO(), current, metav1.UpdateOptions{})
		return err
	}))
	updateLegacyStatus(func(status *crdv1beta1.EgressStatus) {
		status.Conditions = append(status.Conditions, crdv1beta1.EgressCondition{
			Type: "Other", Status: v1.ConditionFalse, Reason: "Pending", Message: "another condition",
			LastTransitionTime: metav1.Now(),
		})
	})
	converted, err = data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	condition = meta.FindStatusCondition(converted.Status.Conditions, "Ready")
	require.NotNil(t, condition)
	require.Positive(t, converted.Generation)
	assert.Equal(t, converted.Generation, condition.ObservedGeneration)
	assert.NotNil(t, meta.FindStatusCondition(converted.Status.Conditions, "Other"))
	updateLegacyStatus(func(status *crdv1beta1.EgressStatus) {
		status.Conditions[0].Message = "updated by a legacy client"
	})
	converted, err = data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	condition = meta.FindStatusCondition(converted.Status.Conditions, "Ready")
	require.NotNil(t, condition)
	assert.Equal(t, "updated by a legacy client", condition.Message)
	assert.Zero(t, condition.ObservedGeneration)
	updateLegacyStatus(func(status *crdv1beta1.EgressStatus) {
		status.Conditions = status.Conditions[1:]
	})
	converted, err = data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Nil(t, meta.FindStatusCondition(converted.Status.Conditions, "Ready"))
}

func testEgressLegacyClientCompatibility(t *testing.T, data *TestData) {
	skipIfNotIPv4Cluster(t)
	skipIfNotIPv6Cluster(t)
	ctx := context.Background()
	v1Egresses := data.CRDClient.CrdV1beta1().Egresses()
	v2Egresses := data.CRDClient.CrdV1beta2().Egresses()
	pools := data.CRDClient.CrdV1beta2().ExternalIPPools()
	for _, tc := range []struct {
		name, cidr, ip, newCIDR, newIP string
	}{
		{"IPv4 to IPv6", "169.254.104.0/30", "169.254.104.1", "2021:3::100/124", "2021:3::101"},
		{"IPv6 to IPv4", "2021:3::200/124", "2021:3::201", "169.254.105.0/30", "169.254.105.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := data.createExternalIPPool(t, "legacy-family-pool-", []v1beta2.IPRange{{CIDR: tc.cidr}},
				nil, nil, map[string]string{v1.LabelHostname: nodeName(0)})
			t.Cleanup(func() { assert.NoError(t, pools.Delete(ctx, pool.Name, metav1.DeleteOptions{})) })
			// Native v1beta1 admission checks allocator state for explicitly requested IPs.
			require.NoError(t, wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, defaultTimeout, true,
				func(ctx context.Context) (bool, error) {
					current, err := pools.Get(ctx, pool.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					return current.Status.Usage.Total > 0, nil
				}))
			legacy, err := v1Egresses.Create(ctx, &crdv1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "legacy-family-egress-"},
				Spec: crdv1beta1.EgressSpec{
					AppliedTo: crdv1beta1.AppliedTo{PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"egress-conversion-test": pool.Name},
					}},
					EgressIP: tc.ip, ExternalIPPool: pool.Name,
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, v1Egresses.Delete(ctx, legacy.Name, metav1.DeleteOptions{})) })
			// A v1beta2 status write must not give the legacy object an implicit family selection or reserved annotation.
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current, err := v2Egresses.Get(ctx, legacy.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				assert.Empty(t, current.Spec.IPFamilies)
				current.Status.EgressIPs = []string{tc.ip}
				_, err = v2Egresses.UpdateStatus(ctx, current, metav1.UpdateOptions{})
				return err
			}))
			// Reconstruct a full v1beta1 PUT as an old client would, without copying server-added annotations.
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current, err := v1Egresses.Get(ctx, legacy.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				assert.NotContains(t, current.Annotations, "crd.antrea.io/conversion-data")
				_, err = v1Egresses.Update(ctx, &crdv1beta1.Egress{
					ObjectMeta: metav1.ObjectMeta{Name: current.Name, ResourceVersion: current.ResourceVersion},
					Spec:       legacy.Spec,
				}, metav1.UpdateOptions{})
				return err
			}))
			require.NoError(t, pools.Delete(ctx, pool.Name, metav1.DeleteOptions{}))
			_, err = pools.Create(ctx, &v1beta2.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: pool.Name},
				Spec: v1beta2.ExternalIPPoolSpec{
					IPRanges: []v1beta2.IPRange{{CIDR: tc.newCIDR}}, NodeSelector: pool.Spec.NodeSelector,
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			require.NoError(t, wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, defaultTimeout, true,
				func(ctx context.Context) (bool, error) {
					current, err := v2Egresses.Get(ctx, legacy.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					return getEgressIP(current) == tc.newIP && len(current.Spec.IPFamilies) == 0, nil
				}))
		})
	}
}

func testEgressClientIP(t *testing.T, data *TestData) {
	type server struct {
		localIP0, localIP1, serverIP string
		prefixLen                    int
	}
	for _, tt := range []struct {
		name    string
		servers []server
	}{
		{name: "ipv4-cluster", servers: []server{{"1.1.1.10", "1.1.1.11", "1.1.1.20", 24}}},
		{name: "ipv6-cluster", servers: []server{{"2021::aaa1", "2021::aaa2", "2021::aaa3", 124}}},
		{name: "dual-stack-cluster", servers: []server{
			{"2021:2::aaa1", "2021:2::aaa2", "2021:2::aaaf", 124},
			{"1.1.2.10", "1.1.2.11", "1.1.2.20", 24},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			egressNode := controlPlaneNodeName()
			servers := slices.Clone(tt.servers)
			var egressIPs []string
			for _, server := range servers {
				if utilnet.IsIPv6String(server.serverIP) {
					skipIfNotIPv6Cluster(t)
					egressIPs = append(egressIPs, controlPlaneNodeIPv6())
				} else {
					skipIfNotIPv4Cluster(t)
					egressIPs = append(egressIPs, controlPlaneNodeIPv4())
				}
			}
			for i, server := range servers {
				name := fmt.Sprintf("egress-server-%s-%d", tt.name, i)
				cmd, _ := getCommandInFakeExternalNetwork("/agnhost netexec", server.prefixLen, server.serverIP, server.localIP0, utilnet.IsIPv6String(server.serverIP), server.localIP1)
				require.NoError(t, NewPodBuilder(name, data.testNamespace, agnhostImage).OnNode(egressNode).
					WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data))
				defer deletePodWrapper(t, data, data.testNamespace, name)
				require.NoError(t, data.podWaitForRunning(defaultTimeout, name, data.testNamespace))
			}
			localPod, remotePod := "localpod-"+tt.name, "remotepod-"+tt.name
			for pod, node := range map[string]string{localPod: egressNode, remotePod: workerNodeName(1)} {
				require.NoError(t, data.createToolboxPodOnNode(pod, data.testNamespace, node, false))
				defer deletePodWrapper(t, data, data.testNamespace, pod)
				require.NoError(t, data.podWaitForRunning(defaultTimeout, pod, data.testNamespace))
			}
			// Only Pods on the Egress Node can reach its fake external networks before Egress is added.
			for _, server := range servers {
				assertClientIP(data, t, localPod, toolboxContainerName, server.serverIP, server.localIP0, server.localIP1)
				assertConnError(data, t, remotePod, toolboxContainerName, server.serverIP)
			}

			egress, err := data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), &v1beta2.Egress{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "egress-"},
				Spec: v1beta2.EgressSpec{
					AppliedTo: v1beta2.EgressAppliedTo{PodSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "antrea-e2e", Operator: metav1.LabelSelectorOpExists},
					}}},
					EgressIPs: egressIPs,
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err = data.waitForEgressRealized(egress)
			require.NoError(t, err)
			assert.Equal(t, egressNode, egress.Status.EgressNode)
			checkTraffic := func(pods ...string) {
				t.Helper()
				for i, server := range servers {
					for _, pod := range pods {
						assertClientIP(data, t, pod, toolboxContainerName, server.serverIP, egress.Spec.EgressIPs[i])
					}
				}
			}
			checkTraffic(localPod, remotePod)

			t.Log("Checking the first connection from a Pod created after the Egress")
			var commands []string
			for i, server := range servers {
				clientIP := egress.Spec.EgressIPs[i]
				if utilnet.IsIPv6String(clientIP) {
					clientIP = "[" + clientIP + "]"
				}
				commands = append(commands, fmt.Sprintf("wget -T 3 -t 1 -O - %s | grep -F '%s:'", getHTTPURLFromIPPort(server.serverIP, 8080, "clientip"), clientIP))
			}
			initialIPChecker := "initial-ip-checker-" + tt.name
			require.NoError(t, NewPodBuilder(initialIPChecker, data.testNamespace, agnhostImage).OnNode(egressNode).
				WithCommand([]string{"sh", "-c", strings.Join(commands, " && ")}).Create(data))
			defer data.DeletePod(data.testNamespace, initialIPChecker)
			_, err = data.PodWaitFor(timeout, initialIPChecker, data.testNamespace, func(pod *v1.Pod) (bool, error) {
				if pod.Status.Phase == v1.PodFailed {
					return false, fmt.Errorf("initial client IP check failed")
				}
				return pod.Status.Phase == v1.PodSucceeded, nil
			})
			require.NoError(t, err)

			updateEgress := func(updateSpec func(*v1beta2.EgressSpec)) {
				t.Helper()
				require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
					current, err := data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
					if err != nil {
						return err
					}
					updateSpec(&current.Spec)
					current, err = data.CRDClient.CrdV1beta2().Egresses().Update(context.TODO(), current, metav1.UpdateOptions{})
					if err == nil {
						egress = current
					}
					return err
				}))
				egress, err = data.waitForEgressRealized(egress)
				require.NoError(t, err)
				assert.Equal(t, egressNode, egress.Status.EgressNode)
			}
			if len(servers) == 2 {
				// Reordering the same pair must preserve local and remote forwarding and the ordered status.
				updateEgress(func(spec *v1beta2.EgressSpec) { slices.Reverse(spec.EgressIPs) })
				slices.Reverse(servers)
				checkTraffic(localPod, remotePod)
			}
			for _, selectedPod := range []string{remotePod, localPod} {
				t.Logf("Updating the Egress's AppliedTo to %s only", selectedPod)
				updateEgress(func(spec *v1beta2.EgressSpec) {
					spec.AppliedTo.PodSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": selectedPod}}
				})
				checkTraffic(selectedPod)
				for _, server := range servers {
					if selectedPod == remotePod {
						assertClientIP(data, t, localPod, toolboxContainerName, server.serverIP, server.localIP0, server.localIP1)
					} else {
						assertConnError(data, t, remotePod, toolboxContainerName, server.serverIP)
					}
				}
			}

			// Change each address independently, checking that the other family's traffic still works.
			for i, server := range servers {
				updateEgress(func(spec *v1beta2.EgressSpec) { spec.EgressIPs[i] = server.localIP1 })
				checkTraffic(localPod)
				for _, server := range servers {
					assertConnError(data, t, remotePod, toolboxContainerName, server.serverIP)
				}
			}
			require.NoError(t, data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{}))
			for _, server := range servers {
				assertClientIP(data, t, localPod, toolboxContainerName, server.serverIP, server.localIP0, server.localIP1)
				assertConnError(data, t, remotePod, toolboxContainerName, server.serverIP)
			}
		})
	}
}

func testEgressClientIPFromVLANSubnet(t *testing.T, data *TestData) {
	skipIfEgressSeparateSubnetDisabled(t)
	type externalNetwork struct {
		serverIP, subnet, gateway string
		family                    v1.IPFamily
	}
	ipv4 := externalNetwork{externalInfo.externalServerIPv4, externalInfo.vlanSubnetIPv4, externalInfo.vlanGatewayIPv4, v1.IPv4Protocol}
	ipv6 := externalNetwork{externalInfo.externalServerIPv6, externalInfo.vlanSubnetIPv6, externalInfo.vlanGatewayIPv6, v1.IPv6Protocol}
	for _, tt := range []struct {
		name     string
		networks []externalNetwork
	}{
		{name: "ipv4-cluster", networks: []externalNetwork{ipv4}},
		{name: "ipv6-cluster", networks: []externalNetwork{ipv6}},
		{name: "dual-stack-cluster", networks: []externalNetwork{ipv6, ipv4}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var ranges []v1beta2.IPRange
			var subnets []v1beta2.SubnetInfo
			var families []v1.IPFamily
			var defaultClientIPs []string
			for _, network := range tt.networks {
				if network.serverIP == "" || network.subnet == "" || network.gateway == "" {
					t.Skipf("Skipping test as the external server or VLAN subnet configuration for %s is not set", network.family)
				}
				if network.family == v1.IPv6Protocol {
					skipIfNotIPv6Cluster(t)
					defaultClientIPs = append(defaultClientIPs, workerNodeIPv6(1))
				} else {
					skipIfNotIPv4Cluster(t)
					defaultClientIPs = append(defaultClientIPs, workerNodeIPv4(1))
				}
				gatewayIP := net.ParseIP(network.gateway)
				require.NotNil(t, gatewayIP)
				_, cidr, err := net.ParseCIDR(network.subnet)
				require.NoError(t, err)
				prefixLength, _ := cidr.Mask.Size()
				// Reserve one address per family, immediately after the gateway.
				ranges = append(ranges, v1beta2.IPRange{Start: ip.NextIP(gatewayIP).String(), End: ip.NextIP(gatewayIP).String()})
				subnets = append(subnets, v1beta2.SubnetInfo{Gateway: network.gateway, PrefixLength: int32(prefixLength), VLAN: int32(externalInfo.vlanID)})
				families = append(families, network.family)
			}
			clientPod1 := fmt.Sprintf("clientpod1-%s", tt.name)
			clientPod2 := fmt.Sprintf("clientpod2-%s", tt.name)
			for _, pod := range []string{clientPod1, clientPod2} {
				require.NoError(t, data.createToolboxPodOnNode(pod, data.testNamespace, workerNodeName(1), false))
				defer deletePodWrapper(t, data, data.testNamespace, pod)
				require.NoError(t, data.podWaitForRunning(defaultTimeout, pod, data.testNamespace))
			}
			pool := data.createExternalIPPool(t, "pool-vlan", ranges, subnets, nil, nil)
			defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})
			egress := data.createEgress(t, "egress-vlan", nil, map[string]string{"antrea-e2e": clientPod1}, pool.Name, "", nil, families...)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err := data.waitForEgressRealized(egress)
			require.NoError(t, err)
			expectedConditions := []metav1.Condition{
				{Type: v1beta2.IPAssigned, Status: metav1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "EgressIPs are successfully allocated"},
			}
			assert.True(t, k8s.SemanticIgnoringTime.DeepEqual(expectedConditions, egress.Status.Conditions), "Unexpected Egress conditions: %v", egress.Status.Conditions)
			for i, network := range tt.networks {
				assertClientIP(data, t, clientPod1, toolboxContainerName, network.serverIP, egress.Spec.EgressIPs[i])
				assertClientIP(data, t, clientPod2, toolboxContainerName, network.serverIP, defaultClientIPs[i])
			}

			t.Log("Updating the Egress's AppliedTo to clientPod2 only")
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current, err := data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				current.Spec.AppliedTo.PodSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientPod2}}
				current, err = data.CRDClient.CrdV1beta2().Egresses().Update(context.TODO(), current, metav1.UpdateOptions{})
				if err == nil {
					egress = current
				}
				return err
			}))
			for i, network := range tt.networks {
				assertClientIP(data, t, clientPod1, toolboxContainerName, network.serverIP, defaultClientIPs[i])
				assertClientIP(data, t, clientPod2, toolboxContainerName, network.serverIP, egress.Spec.EgressIPs[i])
			}

			t.Log("Deleting the Egress")
			require.NoError(t, data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{}))
			for i, network := range tt.networks {
				assertClientIP(data, t, clientPod1, toolboxContainerName, network.serverIP, defaultClientIPs[i])
				assertClientIP(data, t, clientPod2, toolboxContainerName, network.serverIP, defaultClientIPs[i])
			}
		})
	}
}

func testEgressCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name               string
		ipRanges           []v1beta2.IPRange
		families           []v1.IPFamily
		nodeSelector       metav1.LabelSelector
		expectedEgressIPs  []string
		expectedNodes      sets.Set[string]
		expectedTotal      int64
		expectedConditions []metav1.Condition
	}{
		{
			name:     "single matching Node",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIPs: []string{"169.254.100.1"},
			expectedNodes:     sets.New[string](nodeName(0)),
			expectedTotal:     2,
			expectedConditions: []metav1.Condition{
				{Type: v1beta2.IPAssigned, Status: metav1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "EgressIPs are successfully allocated"},
			},
		},
		{
			name:     "single matching Node with IPv6 range",
			ipRanges: []v1beta2.IPRange{{CIDR: "2021:1::aaa0/124"}},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIPs: []string{"2021:1::aaa1"},
			expectedNodes:     sets.New[string](nodeName(0)),
			expectedTotal:     15,
			expectedConditions: []metav1.Condition{
				{Type: v1beta2.IPAssigned, Status: metav1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "EgressIPs are successfully allocated"},
			},
		},
		{
			name:     "two matching Nodes",
			ipRanges: []v1beta2.IPRange{{Start: "169.254.101.10", End: "169.254.101.11"}},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedEgressIPs: []string{"169.254.101.10"},
			expectedNodes:     sets.New[string](nodeName(0), nodeName(1)),
			expectedTotal:     2,
			expectedConditions: []metav1.Condition{
				{Type: v1beta2.IPAssigned, Status: metav1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "EgressIPs are successfully allocated"},
			},
		},
		{
			name:     "no matching Node",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.102.0/30"}},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo": "bar",
				},
			},
			expectedEgressIPs: []string{"169.254.102.1"},
			expectedNodes:     sets.New[string](),
			expectedTotal:     2,
			expectedConditions: []metav1.Condition{
				{Type: v1beta2.IPAssigned, Status: metav1.ConditionFalse, Reason: "AssignmentError", Message: "Failed to assign the IP to EgressNode: no Node available"},
				{Type: v1beta2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "EgressIPs are successfully allocated"},
			},
		},
	}
	for _, single := range tests {
		if utilnet.IsIPv6String(single.expectedEgressIPs[0]) {
			continue
		}
		for _, families := range [][]v1.IPFamily{{v1.IPv4Protocol, v1.IPv6Protocol}, {v1.IPv6Protocol, v1.IPv4Protocol}} {
			dual := single
			dual.name += fmt.Sprintf(" dual-stack %s first", families[0])
			dual.ipRanges = append(slices.Clone(single.ipRanges), v1beta2.IPRange{CIDR: "2021:100::/124"})
			dual.families = families
			dual.expectedEgressIPs = []string{single.expectedEgressIPs[0], "2021:100::1"}
			if families[0] == v1.IPv6Protocol {
				slices.Reverse(dual.expectedEgressIPs)
			}
			dual.expectedTotal += 15
			tests = append(tests, dual)
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, ip := range tt.expectedEgressIPs {
				if utilnet.IsIPv6String(ip) {
					skipIfNotIPv6Cluster(t)
				} else {
					skipIfNotIPv4Cluster(t)
				}
			}
			pool := data.createExternalIPPool(t, "crud-pool-", tt.ipRanges, nil, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "crud-egress-", nil, map[string]string{"foo": "bar"}, pool.Name, "", nil, tt.families...)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			// Use Poll to wait the interval before the first run to detect the case that the IP is assigned to any Node
			// when it's not supposed to.
			err := wait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, 3*time.Second, false, func(ctx context.Context) (done bool, err error) {
				current, err := data.CRDClient.CrdV1beta2().Egresses().Get(ctx, egress.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				egress = current
				if !slices.Equal(egress.Spec.EgressIPs, tt.expectedEgressIPs) {
					return false, nil
				}
				if !k8s.SemanticIgnoringTime.DeepEqual(tt.expectedConditions, egress.Status.Conditions) {
					return false, nil
				}
				if tt.expectedNodes.Len() == 0 {
					if egress.Status.EgressNode != "" {
						return false, fmt.Errorf("this Egress shouldn't be assigned to any Node")
					}
				} else {
					if !tt.expectedNodes.Has(egress.Status.EgressNode) {
						return false, nil
					}
				}
				return true, nil
			})
			require.NoError(t, err, "Expected egressIP=%s nodeName in %s, got egressIP=%s nodeName=%s", tt.expectedEgressIPs, sets.List(tt.expectedNodes), egress.Spec.EgressIPs, egress.Status.EgressNode)
			if egress.Status.EgressNode != "" {
				assert.Equal(t, tt.expectedEgressIPs, egress.Status.EgressIPs)
				for _, ip := range tt.expectedEgressIPs {
					exists, err := hasIP(data, egress.Status.EgressNode, ip)
					require.NoError(t, err, "Failed to check if IP exists on Node")
					assert.True(t, exists, "Didn't find desired IP %s on Node", ip)
				}
				expectedMessage := fmt.Sprintf("Assigned Egress %s with %s on Node %s", egress.Name, egressIPDescription(tt.expectedEgressIPs), egress.Status.EgressNode)
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					events, err := data.clientset.EventsV1().Events("").List(context.TODO(), metav1.ListOptions{
						FieldSelector: fmt.Sprintf("regarding.name=%s", egress.Name),
					})
					if assert.NoError(c, err) && assert.Len(c, events.Items, 1) {
						assert.Equal(c, expectedMessage, events.Items[0].Note)
					}
				}, 2*time.Second, 200*time.Millisecond)
			}

			checkEIPStatus := func(expectedUsed int64) {
				var gotUsed, gotTotal int64
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, 2*time.Second, true,
					func(ctx context.Context) (done bool, err error) {
						pool, err := data.CRDClient.CrdV1beta2().ExternalIPPools().Get(ctx, pool.Name, metav1.GetOptions{})
						if err != nil {
							return false, fmt.Errorf("failed to get ExternalIPPool: %v", err)
						}
						gotUsed, gotTotal = pool.Status.Usage.Used, pool.Status.Usage.Total
						if expectedUsed != pool.Status.Usage.Used {
							return false, nil
						}
						if tt.expectedTotal != pool.Status.Usage.Total {
							return false, nil
						}
						return true, nil
					})
				require.NoError(t, err, "ExternalIPPool status not match: expectedTotal=%d, got=%d, expectedUsed=%d, got=%d", tt.expectedTotal, gotTotal, expectedUsed, gotUsed)
			}
			checkEIPStatus(int64(len(tt.expectedEgressIPs)))

			err = data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Egress")
			if egress.Status.EgressNode != "" {
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
					func(ctx context.Context) (done bool, err error) {
						for _, ip := range tt.expectedEgressIPs {
							exists, err := hasIP(data, egress.Status.EgressNode, ip)
							if err != nil {
								return false, fmt.Errorf("check ip error: %v", err)
							}
							if exists {
								return false, nil
							}
						}
						return true, nil
					})
				require.NoError(t, err, "Found stale IP (%s) exists on Node (%s)", egress.Spec.EgressIPs, egress.Status.EgressNode)
			}
			checkEIPStatus(0)
		})
	}
}

func testEgressIPFamilySelection(t *testing.T, data *TestData) {
	skipIfNotIPv4Cluster(t)
	skipIfNotIPv6Cluster(t)

	pool := &v1beta2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "family-selection-pool-"},
		Spec: v1beta2.ExternalIPPoolSpec{
			IPRanges: []v1beta2.IPRange{
				{CIDR: "169.254.103.0/30"},
				{CIDR: "2021:1::aab0/124"},
			},
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{
				v1.LabelHostname: nodeName(0),
			}},
		},
	}
	pool, err := data.CRDClient.CrdV1beta2().ExternalIPPools().Create(context.TODO(), pool, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

	newEgress := func() *v1beta2.Egress {
		return &v1beta2.Egress{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "family-selection-egress-"},
			Spec: v1beta2.EgressSpec{
				AppliedTo:      v1beta2.EgressAppliedTo{},
				ExternalIPPool: pool.Name,
			},
		}
	}
	t.Run("automatic single-stack", func(t *testing.T) {
		automatic, err := data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), newEgress(), metav1.CreateOptions{})
		require.NoError(t, err)
		defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), automatic.Name, metav1.DeleteOptions{})
		automatic, err = data.waitForEgressRealized(automatic)
		require.NoError(t, err)
		assert.Len(t, automatic.Spec.EgressIPs, 1)
	})

	for _, tc := range []struct {
		name     string
		ips      []string
		families []v1.IPFamily
		err      string
	}{
		{
			name:     "automatic IPv6 first",
			families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
		},
		{
			name: "IPv4 first", ips: []string{"169.254.103.1", "2021:1::aab1"},
			families: []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol},
		},
		{
			name: "IPv6 first", ips: []string{"2021:1::aab1", "169.254.103.1"},
			families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
		},
		{
			name: "IPv6 first without families", ips: []string{"2021:1::aab1", "169.254.103.1"},
		},
		{
			name: "IPv4 first with reversed families", ips: []string{"169.254.103.1", "2021:1::aab1"},
			families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
			err:      "spec.egressIPs[0] has IP family IPv4 which does not match spec.ipFamilies[0] IPv6",
		},
		{
			name: "IPv6 first with reversed families", ips: []string{"2021:1::aab1", "169.254.103.1"},
			families: []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol},
			err:      "spec.egressIPs[0] has IP family IPv6 which does not match spec.ipFamilies[0] IPv4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			egress := newEgress()
			egress.Spec.EgressIPs = tc.ips
			egress.Spec.IPFamilies = tc.families
			egress, err := data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err = data.waitForEgressRealized(egress)
			require.NoError(t, err)
			require.Len(t, egress.Status.EgressIPs, 2)
			if len(tc.ips) > 0 {
				assert.Equal(t, tc.ips, egress.Status.EgressIPs)
			}
			for i, family := range tc.families {
				assert.Equal(t, family == v1.IPv6Protocol, utilnet.IsIPv6String(egress.Status.EgressIPs[i]))
			}
		})
	}

	egress := newEgress()
	egress.Spec.IPFamilies = []v1.IPFamily{v1.IPv6Protocol}
	egress, err = data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	egress, err = data.waitForEgressRealized(egress)
	require.NoError(t, err)
	assert.Equal(t, "2021:1::aab1", getEgressIP(egress))
}

func testEgressUpdateEgressIP(t *testing.T, data *TestData) {
	tests := []struct {
		name              string
		originalNode      string
		newNode           string
		originalIPRanges  []v1beta2.IPRange
		originalEgressIPs []string
		newIPRanges       []v1beta2.IPRange
		newEgressIPs      []string
		families          []v1.IPFamily
	}{
		{
			name:              "same Node",
			originalNode:      nodeName(0),
			newNode:           nodeName(0),
			originalIPRanges:  []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}},
			originalEgressIPs: []string{"169.254.100.1"},
			newIPRanges:       []v1beta2.IPRange{{CIDR: "169.254.101.0/30"}},
			newEgressIPs:      []string{"169.254.101.1"},
		},
		{
			name:              "different Nodes",
			originalNode:      nodeName(0),
			newNode:           nodeName(1),
			originalIPRanges:  []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}},
			originalEgressIPs: []string{"169.254.100.1"},
			newIPRanges:       []v1beta2.IPRange{{CIDR: "169.254.101.0/30"}},
			newEgressIPs:      []string{"169.254.101.1"},
		},
		{
			name:              "different Nodes in IPv6 cluster",
			originalNode:      nodeName(0),
			newNode:           nodeName(1),
			originalIPRanges:  []v1beta2.IPRange{{CIDR: "2021:2::aaa0/124"}},
			originalEgressIPs: []string{"2021:2::aaa1"},
			newIPRanges:       []v1beta2.IPRange{{CIDR: "2021:2::bbb0/124"}},
			newEgressIPs:      []string{"2021:2::bbb1"},
		},
	}
	for _, single := range tests {
		if utilnet.IsIPv6String(single.originalEgressIPs[0]) {
			continue
		}
		dual := single
		dual.name += " dual-stack"
		dual.originalIPRanges = append(slices.Clone(single.originalIPRanges), v1beta2.IPRange{CIDR: "2021:2::aaa0/124"})
		dual.newIPRanges = append(slices.Clone(single.newIPRanges), v1beta2.IPRange{CIDR: "2021:2::bbb0/124"})
		dual.originalEgressIPs = []string{single.originalEgressIPs[0], "2021:2::aaa1"}
		dual.newEgressIPs = []string{single.newEgressIPs[0], "2021:2::bbb1"}
		dual.families = []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol}
		tests = append(tests, dual)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, ip := range tt.originalEgressIPs {
				if utilnet.IsIPv6String(ip) {
					skipIfNotIPv6Cluster(t)
				} else {
					skipIfNotIPv4Cluster(t)
				}
			}
			originalPool := data.createExternalIPPool(t, "originalpool-", tt.originalIPRanges, nil, nil, map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), originalPool.Name, metav1.DeleteOptions{})
			newPool := data.createExternalIPPool(t, "newpool-", tt.newIPRanges, nil, nil, map[string]string{v1.LabelHostname: tt.newNode})
			defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), newPool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, originalPool.Name, "", nil, tt.families...)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err := data.checkEgressState(egress.Name, tt.originalEgressIPs, tt.originalNode, "", time.Second)
			require.NoError(t, err)

			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				toUpdate, err := data.CRDClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				toUpdate.Spec.ExternalIPPool = newPool.Name
				toUpdate.Spec.EgressIPs = tt.newEgressIPs
				_, err = data.CRDClient.CrdV1beta2().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
				return err
			}), "Failed to update Egress")
			expectedMessages := []string{
				fmt.Sprintf("Assigned Egress %s with %s on Node %s", egress.Name, egressIPDescription(tt.originalEgressIPs), tt.originalNode),
				fmt.Sprintf("Unassigned Egress %s with %s from Node %s", egress.Name, egressIPDescription(tt.originalEgressIPs), tt.originalNode),
				fmt.Sprintf("Assigned Egress %s with %s on Node %s", egress.Name, egressIPDescription(tt.newEgressIPs), tt.newNode),
			}
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				events, err := data.clientset.EventsV1().Events("").List(context.TODO(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("regarding.name=%s", egress.Name),
				})
				if assert.NoError(c, err) && assert.Len(c, events.Items, len(expectedMessages)) {
					recordedMessages := []string{}
					for _, items := range events.Items {
						recordedMessages = append(recordedMessages, items.Note)
					}
					assert.Equal(c, expectedMessages[0], recordedMessages[0])
					// Assignment and unassignment on different Nodes may be recorded in either order.
					assert.ElementsMatch(c, expectedMessages[1:], recordedMessages[1:])
				}
			}, 2*time.Second, 200*time.Millisecond)

			_, err = data.checkEgressState(egress.Name, tt.newEgressIPs, tt.newNode, "", time.Second)
			require.NoError(t, err)
			err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
				func(ctx context.Context) (done bool, err error) {
					for _, ip := range tt.originalEgressIPs {
						exists, err := hasIP(data, tt.originalNode, ip)
						if err != nil {
							return false, fmt.Errorf("check ip error: %v", err)
						}
						if exists {
							return false, nil
						}
					}
					return true, nil
				})
			require.NoError(t, err, "Found stale IP (%s) exists on Node (%s)", tt.originalEgressIPs, tt.originalNode)
		})
	}
}

func testEgressUpdateNodeSelector(t *testing.T, data *TestData) {
	// This test relies on IP neighbors to determine the effective Egress IP and requires all Nodes to be in the same subnet.
	// In hybrid mode, Nodes are in different subnets, so the test is skipped.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
	tests := []struct {
		name     string
		ipRanges []v1beta2.IPRange
		families []v1.IPFamily
	}{
		{
			name:     "IPv4 cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}},
			families: []v1.IPFamily{v1.IPv4Protocol},
		},
		{
			name:     "IPv6 cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "2021:3::aaa1/124"}},
			families: []v1.IPFamily{v1.IPv6Protocol},
		},
		{
			name:     "dual-stack cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}, {CIDR: "2021:5::/124"}},
			families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, family := range tt.families {
				if family == v1.IPv4Protocol {
					skipIfNotIPv4Cluster(t)
				} else {
					skipIfNotIPv6Cluster(t)
				}
			}
			updateNodeSelector := func(poolName, evictNode string, ensureExists bool) {
				pool, err := data.CRDClient.CrdV1beta2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
				require.NoError(t, err, "Failed to get ExternalIPPool %v", pool)
				newNodes := sets.New[string](pool.Spec.NodeSelector.MatchExpressions[0].Values...)
				if ensureExists {
					newNodes.Insert(evictNode)
				} else {
					newNodes.Delete(evictNode)
				}
				pool.Spec.NodeSelector.MatchExpressions[0].Values = sets.List(newNodes)
				_, err = data.CRDClient.CrdV1beta2().ExternalIPPools().Update(context.TODO(), pool, metav1.UpdateOptions{})
				require.NoError(t, err, "Failed to update ExternalIPPool %v", pool)
			}
			shrinkEgressNodes := func(poolName, evictNode string) {
				// Remove one Node from the node candidates.
				updateNodeSelector(poolName, evictNode, false)
			}
			restoreEgressNodes := func(poolName, evictNode string) {
				// Add the removed Node back to the node candidates.
				updateNodeSelector(poolName, evictNode, true)
			}
			// Egress IP migration should happen fast when it's caused by nodeSelector update.
			// No IP should be left on the evicted Node.
			testEgressMigration(t, data, shrinkEgressNodes, restoreEgressNodes, true, time.Second, tt.ipRanges, tt.families)
		})
	}
}

func testEgressNodeFailure(t *testing.T, data *TestData) {
	// This test relies on IP neighbors to determine the effective Egress IP and requires all Nodes to be in the same subnet.
	// In hybrid mode, Nodes are in different subnets, so the test is skipped.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
	tests := []struct {
		name     string
		ipRanges []v1beta2.IPRange
		families []v1.IPFamily
	}{
		{
			name:     "IPv4 cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}},
			families: []v1.IPFamily{v1.IPv4Protocol},
		},
		{
			name:     "IPv6 cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "2021:4::aaa1/124"}},
			families: []v1.IPFamily{v1.IPv6Protocol},
		},
		{
			name:     "dual-stack cluster",
			ipRanges: []v1beta2.IPRange{{CIDR: "169.254.100.0/30"}, {CIDR: "2021:5::/124"}},
			families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, family := range tt.families {
				if family == v1.IPv4Protocol {
					skipIfNotIPv4Cluster(t)
				} else {
					skipIfNotIPv6Cluster(t)
				}
			}
			signalAgent := func(nodeName, signal string) {
				cmd := fmt.Sprintf("pkill -%s antrea-agent", signal)
				if testOptions.providerName != "kind" {
					cmd = "sudo " + cmd
				}
				rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
				if rc != 0 || err != nil {
					t.Errorf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
						cmd, nodeName, rc, stdout, stderr, err)
				}
			}
			pauseAgent := func(_, evictNode string) {
				// Send "STOP" signal to antrea-agent.
				signalAgent(evictNode, "STOP")
			}
			restoreAgent := func(_, evictNode string) {
				// Send "CONT" signal to antrea-agent.
				signalAgent(evictNode, "CONT")
			}
			// Egress IP migration may take a few seconds when it's caused by Node failure detection.
			// Skip checking Egress IP on the evicted Node because Egress IP will be left on it (no running antrea-agent).
			testEgressMigration(t, data, pauseAgent, restoreAgent, false, 10*time.Second, tt.ipRanges, tt.families)
		})
	}
}

func testEgressMigration(t *testing.T, data *TestData, triggerFunc, revertFunc func(poolName, evictNode string), checkEvictNode bool, timeout time.Duration, ipRanges []v1beta2.IPRange, families []v1.IPFamily) {
	nodeCandidates := sets.New[string](nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   sets.List(nodeCandidates),
		},
	}
	externalIPPoolTwoNodes := data.createExternalIPPool(t, "pool-with-two-nodes-", ipRanges, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta2().ExternalIPPools().Delete(context.TODO(), externalIPPoolTwoNodes.Name, metav1.DeleteOptions{})

	egress := data.createEgress(t, "migration-egress-", nil, map[string]string{"foo": "bar"}, externalIPPoolTwoNodes.Name, "", nil, families...)
	defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	var err error
	egress, err = data.waitForEgressRealized(egress)
	require.NoError(t, err)
	assert.True(t, nodeCandidates.Has(egress.Status.EgressNode))

	fromNode, toNode := nodeName(0), nodeName(1)
	if egress.Status.EgressNode != fromNode {
		fromNode, toNode = nodeName(1), nodeName(0)
	}
	var neighborCheckers []func(string)
	if observerNode := nodeName(2); observerNode != "" {
		for _, ip := range egress.Spec.EgressIPs {
			check, err := setupIPNeighborChecker(data, t, observerNode, fromNode, toNode, ip)
			require.NoError(t, err)
			neighborCheckers = append(neighborCheckers, check)
		}
	} else {
		t.Log("The cluster didn't have enough Nodes, skip IP neighbor check")
	}
	checkIPNeighbor := func(node string) {
		for _, check := range neighborCheckers {
			check(node)
		}
	}

	checkIPNeighbor(fromNode)

	// Trigger Egress IP migration. The EgressIP should be moved to the other Node.
	triggerFunc(externalIPPoolTwoNodes.Name, fromNode)
	// Defer revertFunc to restore the testbed regardless of success or failure.
	defer revertFunc(externalIPPoolTwoNodes.Name, fromNode)
	// Only check evictNode when checkEvictNode is true.
	var otherNodeToCheck string
	if checkEvictNode {
		otherNodeToCheck = fromNode
	}
	_, err = data.checkEgressState(egress.Name, egress.Spec.EgressIPs, toNode, otherNodeToCheck, timeout)
	assert.NoError(t, err)
	checkIPNeighbor(toNode)

	// Revert the operation. The EgressIP should be moved back.
	revertFunc(externalIPPoolTwoNodes.Name, fromNode)
	_, err = data.checkEgressState(egress.Name, egress.Spec.EgressIPs, fromNode, toNode, timeout)
	assert.NoError(t, err)
	checkIPNeighbor(fromNode)
}

func testEgressUpdateBandwidth(t *testing.T, data *TestData) {
	skipIfEgressShapingDisabled(t)
	skipIfHasWindowsNodes(t)
	for caseIndex, tt := range []struct {
		name     string
		families []v1.IPFamily
	}{
		{name: "IPv4", families: []v1.IPFamily{v1.IPv4Protocol}},
		{name: "IPv6", families: []v1.IPFamily{v1.IPv6Protocol}},
		{name: "dual-stack", families: []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bandwidth := &v1beta2.Bandwidth{Rate: "100M", Burst: "200M"}
			egressNode := workerNodeName(1)
			var egressIPs, serverIPs []string
			for i, family := range tt.families {
				serverIP, localIP, prefixLen := fmt.Sprintf("1.1.%d.1", caseIndex+1), fmt.Sprintf("1.1.%d.254", caseIndex+1), 24
				if family == v1.IPv6Protocol {
					skipIfNotIPv6Cluster(t)
					egressIPs = append(egressIPs, workerNodeIPv6(1))
					serverIP, localIP, prefixLen = fmt.Sprintf("2021:%d::1", caseIndex+6), fmt.Sprintf("2021:%d::e", caseIndex+6), 124
				} else {
					skipIfNotIPv4Cluster(t)
					egressIPs = append(egressIPs, workerNodeIPv4(1))
				}
				serverIPs = append(serverIPs, serverIP)
				name := fmt.Sprintf("qos-server-%s-%d", strings.ToLower(tt.name), i)
				cmd, _ := getCommandInFakeExternalNetwork("iperf3 -s", prefixLen, serverIP, localIP, family == v1.IPv6Protocol)
				require.NoError(t, NewPodBuilder(name, data.testNamespace, ToolboxImage).OnNode(egressNode).
					WithCommand([]string{"bash", "-c", cmd}).InHostNetwork().Privileged().Create(data))
				defer deletePodWrapper(t, data, data.testNamespace, name)
				require.NoError(t, data.podWaitForRunning(defaultTimeout, name, data.testNamespace))
			}
			clientPodName := "qos-client-" + strings.ToLower(tt.name)
			require.NoError(t, data.createToolboxPodOnNode(clientPodName, data.testNamespace, egressNode, false))
			defer deletePodWrapper(t, data, data.testNamespace, clientPodName)
			require.NoError(t, data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace))

			egress, err := data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), &v1beta2.Egress{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "egress-qos-"},
				Spec: v1beta2.EgressSpec{
					AppliedTo: v1beta2.EgressAppliedTo{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientPodName}}},
					EgressIPs: egressIPs,
					Bandwidth: bandwidth,
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			defer data.CRDClient.CrdV1beta2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			_, err = data.waitForEgressRealized(egress)
			require.NoError(t, err)

			// Use the same burst and steady-state checks, including tolerance, for each family.
			runIperf := func(serverIP, args string, expectedBandwidth int) {
				t.Helper()
				cmd := fmt.Sprintf("iperf3 -c %s -f m %s | grep sender | awk '{print $7}'", serverIP, args)
				stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPodName, toolboxContainerName, []string{"bash", "-c", cmd})
				require.NoError(t, err, "iperf3 failed: %s", stderr)
				actualBandwidth, err := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
				require.NoError(t, err, "Unexpected iperf3 output: %s", stdout)
				t.Logf("Actual bandwidth to %s: %v Mbits/sec", serverIP, actualBandwidth)
				assert.InEpsilon(t, expectedBandwidth, actualBandwidth, 0.2)
			}
			for i, serverIP := range serverIPs {
				if i > 0 {
					// Both families share a meter. Refill its 200M burst at 100M/s before checking the next family.
					time.Sleep(2 * time.Second)
				}
				runIperf(serverIP, "-t 1", 300)
				runIperf(serverIP, "-O 1", 100)
			}
		})
	}
}

func (data *TestData) checkEgressState(egressName string, expectedIPs []string, expectedNode, otherNode string, timeout time.Duration) (*v1beta2.Egress, error) {
	var egress *v1beta2.Egress
	pollErr := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		egress, err = data.CRDClient.CrdV1beta2().Egresses().Get(ctx, egressName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if !slices.Equal(egress.Spec.EgressIPs, expectedIPs) || !slices.Equal(egress.Status.EgressIPs, expectedIPs) || egress.Status.EgressNode != expectedNode {
			return false, nil
		}
		for _, ip := range expectedIPs {
			// Every IP must be configured on the desired Node and removed from the other Node.
			exists, err := hasIP(data, expectedNode, ip)
			if err != nil || !exists {
				return false, err
			}
			if otherNode != "" {
				exists, err = hasIP(data, otherNode, ip)
				if err != nil || exists {
					return false, err
				}
			}
		}
		return true, nil
	})
	if pollErr != nil {
		return egress, fmt.Errorf("egress did not reach expected state, err: %v, egress: %v, expectedIPs: %v, expectedNode: %s, otherNode: %s", pollErr, egress, expectedIPs, expectedNode, otherNode)
	}
	return egress, nil
}

func egressIPDescription(ips []string) string {
	if len(ips) == 1 {
		return "IP " + ips[0]
	}
	return "IPs " + strings.Join(ips, ", ")
}

func hasIP(data *TestData, nodeName string, ip string) (bool, error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return false, err
	}
	cmd := []string{"ip", "-br", "addr"}
	stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
	if err != nil {
		return false, err
	}
	return strings.Contains(stdout, ip+"/32") || strings.Contains(stdout, ip+"/128"), nil
}

func setupIPNeighborChecker(data *TestData, t *testing.T, observerNode, node1, node2, ip string) (checkIPNeighbor func(string), err error) {
	transportInterface, err := data.GetTransportInterfaceName()
	require.NoError(t, err)

	macAddress1, err := data.GetNodeMACAddress(node1, transportInterface)
	require.NoError(t, err)
	macAddress2, err := data.GetNodeMACAddress(node2, transportInterface)
	require.NoError(t, err)
	nodeToMACAddress := map[string]string{node1: macAddress1, node2: macAddress2}

	antreaPodName, err := data.getAntreaPodOnNode(observerNode)
	require.NoError(t, err)

	// The Egress IP may not be in the same subnet as the primary IP of the transport interface.
	// Adding a direct route for the Egress IP so the Node will query its MAC address, instead of trying to connect via
	// its gateway.
	cmd := []string{"ip", "route", "replace", ip, "dev", transportInterface}
	_, _, err = data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
	require.NoError(t, err, "Failed to add a direct route for Egress IP %s on Node %s", ip, observerNode)

	t.Cleanup(func() {
		cmd := []string{"ip", "route", "del", ip, "dev", transportInterface}
		_, _, err = data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
		require.NoError(t, err, "Failed to delete the direct route for Egress IP %s on Node %s", ip, observerNode)
	})

	checkIPNeighbor = func(expectNode string) {
		check := func(allowEmpty bool) {
			showIPNeighCmd := []string{"ip", "neighbor", "show", ip, "dev", transportInterface}
			// stdout example:
			// 172.18.0.1 lladdr 02:42:c2:60:91:66 STALE
			stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, showIPNeighCmd)
			require.NoError(t, err, "Failed to query lladdr for Egress IP %s on Node %s", ip, observerNode)
			if stdout == "" || strings.Contains(stdout, "FAILED") {
				if !allowEmpty {
					t.Errorf("Didn't get lladdr for Egress IP %s on Node %s", ip, observerNode)
				}
				return
			}
			fields := strings.Fields(stdout)
			require.Len(t, fields, 4)
			llAddr := fields[2]
			assert.Equal(t, nodeToMACAddress[expectNode], llAddr, "lladdr for Egress IP %s didn't match the MAC address of Node %s", ip, expectNode)
		}
		// Before the Node actually connects to the Egress IP, we expect that the lladdr either matches the Egress Node's MAC address or is empty.
		check(true)
		// The protocol must be present when using wget with IPv6 address.
		cmd := []string{"wget", getHTTPURLFromIPPort(ip, 80), "-T", "1", "-t", "1"}
		// We don't care whether it succeeds, just make it connect to the Egress IP to learn its MAC address.
		data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
		// After the Node tries to connect to the Egress IP, we expect that the lladdr matches the Egress Node's MAC address.
		check(false)
	}
	return checkIPNeighbor, nil
}

func (data *TestData) createExternalIPPool(t *testing.T, generateName string, ipRanges []v1beta2.IPRange, subnets []v1beta2.SubnetInfo, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string) *v1beta2.ExternalIPPool {
	pool := &v1beta2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1beta2.ExternalIPPoolSpec{
			IPRanges: ipRanges,
			Subnets:  subnets,
			NodeSelector: metav1.LabelSelector{
				MatchExpressions: matchExpressions,
				MatchLabels:      matchLabels,
			},
		},
	}
	pool, err := data.CRDClient.CrdV1beta2().ExternalIPPools().Create(context.TODO(), pool, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create ExternalIPPool")
	return pool
}

func (data *TestData) createEgress(t *testing.T, generateName string, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string, externalPoolName string, egressIP string, bandwidth *v1beta2.Bandwidth, families ...v1.IPFamily) *v1beta2.Egress {
	egress := &v1beta2.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1beta2.EgressSpec{
			AppliedTo: v1beta2.EgressAppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
			ExternalIPPool: externalPoolName,
			Bandwidth:      bandwidth,
			IPFamilies:     families,
		},
	}
	if egressIP != "" {
		egress.Spec.EgressIPs = []string{egressIP}
	}
	egress, err := data.CRDClient.CrdV1beta2().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create Egress")
	return egress
}

func (data *TestData) waitForEgressRealized(egress *v1beta2.Egress) (*v1beta2.Egress, error) {
	err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, waitEgressRealizedTimeout, true,
		func(ctx context.Context) (done bool, err error) {
			current, err := data.CRDClient.CrdV1beta2().Egresses().Get(ctx, egress.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			egress = current
			return len(egress.Spec.EgressIPs) > 0 &&
				slices.Equal(egress.Spec.EgressIPs, egress.Status.EgressIPs) &&
				egress.Status.EgressNode != "", nil
		})
	if err != nil {
		return nil, fmt.Errorf("wait for Egress %#v realized failed: %v", egress, err)
	}
	return egress, nil
}

func getEgressIP(egress *v1beta2.Egress) string {
	if len(egress.Spec.EgressIPs) != 1 {
		return ""
	}
	return egress.Spec.EgressIPs[0]
}

// assertClientIP asserts the Pod is translated to the provided client IP.
func assertClientIP(data *TestData, t *testing.T, pod, container, serverIP string, clientIPs ...string) {
	var exeErr error
	var stdout, stderr string
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 5*time.Second, false, func(ctx context.Context) (done bool, err error) {
		url := getHTTPURLFromIPPort(serverIP, 8080, "clientip")
		stdout, stderr, exeErr = data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, container, url, 5)
		if exeErr != nil {
			return false, nil
		}

		// The stdout return is in this format: x.x.x.x:port or [xx:xx:xx::x]:port
		host, _, err := net.SplitHostPort(stdout)
		if err != nil {
			return false, nil
		}
		for _, cip := range clientIPs {
			if cip == host {
				return true, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err, "Failed to get expected client IPs %s for Pod %s, stdout: %s, stderr: %s, err: %v", clientIPs, pod, stdout, stderr, exeErr)
}

// assertConnError asserts the Pod is not able to access the API that replies the request's client IP.
func assertConnError(data *TestData, t *testing.T, pod, container, serverIP string) {
	var exeErr error
	var stdout, stderr string
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 2*time.Second, false,
		func(ctx context.Context) (done bool, err error) {
			url := getHTTPURLFromIPPort(serverIP, 8080, "clientip")
			stdout, stderr, exeErr = data.RunCommandFromPod(data.testNamespace, pod, container,
				[]string{"wget", "-O", "-", url, "-T", "1", "-t", "1"})
			if exeErr != nil {
				return true, nil
			}
			return false, nil
		})
	require.NoError(t, err, "Failed to get expected error, stdout: %v, stderr: %v, err: %v", stdout, stderr, exeErr)

}
