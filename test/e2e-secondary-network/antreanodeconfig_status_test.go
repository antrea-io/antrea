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

package e2esecondary

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	antreae2e "antrea.io/antrea/v2/test/e2e"
)

// TestAntreaNodeConfigStatus verifies realization, generation changes, failures,
// draining with a retained empty ANC, selector migration, and asynchronous deletion.
// The runner enables SecondaryNetwork and leaves the static bridge list empty.
func TestAntreaNodeConfigStatus(t *testing.T) {
	require.GreaterOrEqual(t, antreae2e.NodeCount(), 2)
	e2eData, err := antreae2e.SetupTest(t)
	require.NoError(t, err)
	defer antreae2e.TeardownTest(t, e2eData)
	ctx := context.Background()
	client := e2eData.CRDClient.CrdV1alpha1().AntreaNodeConfigs()
	k8sClient, err := kubernetes.NewForConfig(e2eData.KubeConfig)
	require.NoError(t, err)
	const name, bridge = "status-test", "br-status"
	nodeName := antreae2e.NodeName(0)
	otherNode := antreae2e.NodeName(1)
	cfg := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector:     metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/hostname": nodeName}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: bridge}}},
		},
	}
	cfg, err = client.Create(ctx, cfg, metav1.CreateOptions{})
	require.NoError(t, err)
	defer func() {
		if err := client.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			t.Errorf("Delete test ANC: %v", err)
		}
	}()
	data := &testData{e2eTestData: e2eData, networkType: networkTypeVLAN}
	waitStatus := func(t *testing.T, generation int64, status metav1.ConditionStatus, reason string) *crdv1alpha1.AntreaNodeConfig {
		t.Helper()
		var current *crdv1alpha1.AntreaNodeConfig
		err := wait.PollUntilContextTimeout(ctx, time.Second, 90*time.Second, true, func(ctx context.Context) (bool, error) {
			var err error
			current, err = client.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			ready := meta.FindStatusCondition(current.Status.Conditions, "Ready")
			return ready != nil && current.Status.ObservedGeneration == generation && ready.ObservedGeneration == generation && ready.Status == status && (reason == "" || ready.Reason == reason), nil
		})
		require.NoError(t, err, "Waiting for ANC generation %d Ready=%s reason=%s; last object: %+v", generation, status, reason, current)
		return current
	}
	update := func(t *testing.T, change func(*crdv1alpha1.AntreaNodeConfig)) *crdv1alpha1.AntreaNodeConfig {
		t.Helper()
		current, err := client.Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		change(current)
		current, err = client.Update(ctx, current, metav1.UpdateOptions{})
		require.NoError(t, err)
		return current
	}
	verifyReport := func(t *testing.T, node string, current *crdv1alpha1.AntreaNodeConfig) {
		t.Helper()
		info, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, node, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, info.NodeConfigStatus)
		require.NotNil(t, info.NodeConfigStatus.SecondaryNetwork)
		ready := meta.FindStatusCondition(info.NodeConfigStatus.SecondaryNetwork.Conditions, "Ready")
		require.NotNil(t, ready)
		assert.Equal(t, current.UID, info.NodeConfigStatus.ConfigUID)
		assert.Equal(t, current.Generation, ready.ObservedGeneration)
		assert.Equal(t, metav1.ConditionTrue, ready.Status)
		currentNode, err := k8sClient.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, currentNode.UID, info.NodeConfigStatus.NodeUID)
	}
	waitBridgeAbsent := func(t *testing.T, node string) {
		t.Helper()
		require.Eventually(t, func() bool {
			stdout, _, err := e2eData.RunCommandFromAntreaPodOnNode(node, []string{"ovs-vsctl", "list-br"})
			if err != nil {
				return false
			}
			for _, br := range strings.Fields(stdout) {
				if br == bridge {
					return false
				}
			}
			return true
		}, 30*time.Second, time.Second, "Bridge %s must be absent on Node %s", bridge, node)
	}
	cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
	assert.Equal(t, int32(1), cfg.Status.DesiredNodes)
	assert.Equal(t, int32(1), cfg.Status.RealizedNodes)
	assert.Empty(t, cfg.Finalizers)
	verifyReport(t, nodeName, cfg)
	require.NoError(t, data.waitForOVSBridge(nodeName, bridge))

	if !t.Run("AgentRestart", func(t *testing.T) {
		before, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
		require.NoError(t, err)
		require.NoError(t, e2eData.RestartAntreaAgentPods(60*time.Second))
		require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
			info, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if info.NodeConfigStatus == nil || info.NodeConfigStatus.SecondaryNetwork == nil {
				return false, nil
			}
			ready := meta.FindStatusCondition(info.NodeConfigStatus.SecondaryNetwork.Conditions, "Ready")
			return info.PodRef.Name != before.PodRef.Name && info.NodeConfigStatus.ConfigUID == cfg.UID &&
				ready != nil && ready.ObservedGeneration == cfg.Generation && ready.Status == metav1.ConditionTrue, nil
		}))
		cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
		verifyReport(t, nodeName, cfg)
	}) {
		return
	}

	if !t.Run("FailureAndRecovery", func(t *testing.T) {
		cfg = update(t, func(current *crdv1alpha1.AntreaNodeConfig) {
			current.Spec.SecondaryNetwork.OVSBridges[0].PhysicalInterfaces = []crdv1alpha1.OVSPhysicalInterfaceConfig{{Name: "missing-status"}}
		})
		failed := waitStatus(t, cfg.Generation, metav1.ConditionFalse, "ReconcileFailed")
		assert.Zero(t, failed.Status.RealizedNodes)
		cfg = update(t, func(current *crdv1alpha1.AntreaNodeConfig) {
			current.Spec.SecondaryNetwork.OVSBridges[0].PhysicalInterfaces = nil
		})
		cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
	}) {
		return
	}

	if !t.Run("RemoveSecondaryNetworkWhileInUse", func(t *testing.T) {
		pod := &testPodInfo{podName: "status-drain", nodeName: nodeName, interfaceNetworks: map[string]string{"eth1": "vlan-net1"}}
		data.pods = []*testPodInfo{pod}
		require.NoError(t, data.createPods(t, e2eData.GetTestNamespace()))
		require.NoError(t, data.verifySecondaryInterfaces(t, ipFamilyIPv4), "Wait for a secondary interface before requesting cleanup")
		uid := cfg.UID
		cfg = update(t, func(current *crdv1alpha1.AntreaNodeConfig) { current.Spec.SecondaryNetwork = nil })
		blocked := waitStatus(t, cfg.Generation, metav1.ConditionFalse, "BridgeInUse")
		assert.Equal(t, uid, blocked.UID)
		assert.Nil(t, blocked.Spec.SecondaryNetwork)
		assert.Equal(t, int32(1), blocked.Status.DesiredNodes)
		assert.Zero(t, blocked.Status.RealizedNodes)
		require.NoError(t, data.waitForOVSBridge(nodeName, bridge), "In-use bridge must remain while draining")
		beforeRestart, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, beforeRestart.NodeConfigStatus)
		require.NoError(t, e2eData.RestartAntreaAgentPods(60*time.Second))
		require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
			info, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if info.NodeConfigStatus == nil || info.NodeConfigStatus.SecondaryNetwork == nil {
				return false, nil
			}
			report := info.NodeConfigStatus
			ready := meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready")
			return info.PodRef.Name != beforeRestart.PodRef.Name &&
				report.ConfigUID == uid && ready != nil && ready.ObservedGeneration == cfg.Generation &&
				ready.Status == metav1.ConditionFalse && ready.Reason == "BridgeInUse", nil
		}))
		blocked = waitStatus(t, cfg.Generation, metav1.ConditionFalse, "BridgeInUse")
		assert.Equal(t, uid, blocked.UID)
		info, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, info.NodeConfigStatus)
		require.NotNil(t, info.NodeConfigStatus.SecondaryNetwork)
		assert.Equal(t, uid, info.NodeConfigStatus.ConfigUID)
		ready := meta.FindStatusCondition(info.NodeConfigStatus.SecondaryNetwork.Conditions, "Ready")
		require.NotNil(t, ready)
		assert.Equal(t, cfg.Generation, ready.ObservedGeneration)
		assert.Equal(t, bridge, info.NodeConfigStatus.SecondaryNetwork.CurrentBridge)
		assert.Empty(t, info.NodeConfigStatus.SecondaryNetwork.DesiredBridge)
		require.NoError(t, e2eData.DeletePod(e2eData.GetTestNamespace(), pod.podName))
		cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
		waitBridgeAbsent(t, nodeName)
		verifyReport(t, nodeName, cfg)
	}) {
		return
	}

	if !t.Run("SelectorMigration", func(t *testing.T) {
		cfg = update(t, func(current *crdv1alpha1.AntreaNodeConfig) {
			current.Spec.SecondaryNetwork = &crdv1alpha1.SecondaryNetworkConfig{OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: bridge}}}
		})
		cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
		cfg = update(t, func(current *crdv1alpha1.AntreaNodeConfig) {
			current.Spec.NodeSelector.MatchLabels["kubernetes.io/hostname"] = otherNode
		})
		cfg = waitStatus(t, cfg.Generation, metav1.ConditionTrue, "Reconciled")
		assert.Equal(t, int32(1), cfg.Status.DesiredNodes)
		assert.Equal(t, int32(1), cfg.Status.RealizedNodes)
		waitBridgeAbsent(t, nodeName)
		require.NoError(t, data.waitForOVSBridge(otherNode, bridge))
		verifyReport(t, otherNode, cfg)
	}) {
		return
	}

	if !t.Run("DeleteWhileInUse", func(t *testing.T) {
		pod := &testPodInfo{podName: "status-delete", nodeName: otherNode, interfaceNetworks: map[string]string{"eth1": "vlan-net1"}}
		data.pods = []*testPodInfo{pod}
		require.NoError(t, data.createPods(t, e2eData.GetTestNamespace()))
		require.NoError(t, data.verifySecondaryInterfaces(t, ipFamilyIPv4), "Wait for a secondary interface before requesting cleanup")
		require.NoError(t, client.Delete(ctx, name, metav1.DeleteOptions{}))
		require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			_, err := client.Get(ctx, name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}))
		require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			info, err := e2eData.CRDClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, otherNode, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if info.NodeConfigStatus == nil || info.NodeConfigStatus.SecondaryNetwork == nil {
				return false, nil
			}
			report := info.NodeConfigStatus
			ready := meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready")
			return report.ConfigUID == "" && ready != nil && ready.Status == metav1.ConditionFalse && ready.Reason == "BridgeInUse", nil
		}))
		require.NoError(t, data.waitForOVSBridge(otherNode, bridge))
		require.NoError(t, e2eData.DeletePod(e2eData.GetTestNamespace(), pod.podName))
		waitBridgeAbsent(t, otherNode)
	}) {
		return
	}
}

// TestAntreaNodeConfigStaticOverride verifies that a rendered ANC is not reported
// ready when the Agent's static secondary bridge configuration takes precedence.
func TestAntreaNodeConfigStaticOverride(t *testing.T) {
	data, err := antreae2e.SetupTest(t)
	require.NoError(t, err)
	defer antreae2e.TeardownTest(t, data)
	const name = "secondary-network-node-pool-all-linux"
	ctx := context.Background()
	require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 90*time.Second, true, func(ctx context.Context) (bool, error) {
		cfg, err := data.CRDClient.CrdV1alpha1().AntreaNodeConfigs().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		ready := meta.FindStatusCondition(cfg.Status.Conditions, "Ready")
		return ready != nil && ready.ObservedGeneration == cfg.Generation && ready.Status == metav1.ConditionFalse && ready.Reason == "OverriddenByStaticConfig" && cfg.Status.RealizedNodes == 0, nil
	}))
}

// TestAntreaNodeConfigDisabledStatus verifies that disabled Agents report their
// capability explicitly and an ANC which was never applied can be deleted.
// The runner disables SecondaryNetwork while keeping AntreaNodeConfig enabled.
func TestAntreaNodeConfigDisabledStatus(t *testing.T) {
	data, err := antreae2e.SetupTest(t)
	require.NoError(t, err)
	defer antreae2e.TeardownTest(t, data)
	ctx := context.Background()
	client := data.CRDClient.CrdV1alpha1().AntreaNodeConfigs()
	cfg, err := client.Create(ctx, &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "status-disabled"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector:     metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/os": "linux"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: "br-disabled"}}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer func() {
		if err := client.Delete(ctx, cfg.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			t.Errorf("Delete disabled ANC: %v", err)
		}
	}()
	require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		current, err := client.Get(ctx, cfg.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		ready := meta.FindStatusCondition(current.Status.Conditions, "Ready")
		return ready != nil && ready.Status == metav1.ConditionFalse && ready.Reason == "FeatureDisabled" && len(current.Finalizers) == 0, nil
	}))
	require.NoError(t, client.Delete(ctx, cfg.Name, metav1.DeleteOptions{}))
	require.NoError(t, wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := client.Get(ctx, cfg.Name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}))
}
