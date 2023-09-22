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

package memberlist

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/consistenthash"
	"antrea.io/antrea/pkg/apis"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	labelsWindowsOS = map[string]string{v1.LabelOSStable: "windows"}
	labelsLinuxOS   = map[string]string{v1.LabelOSStable: "linux"}
)

type fakeCluster struct {
	cluster   *Cluster
	clientSet *fake.Clientset
	crdClient *fakeversioned.Clientset
}

func newFakeCluster(nodeConfig *config.NodeConfig, stopCh <-chan struct{}, memberlist Memberlist, objs ...runtime.Object) (*fakeCluster, error) {
	clientset := fake.NewSimpleClientset(objs...)
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()
	crdClient := fakeversioned.NewSimpleClientset()
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	ipPoolInformer := crdInformerFactory.Crd().V1beta1().ExternalIPPools()
	cluster, err := NewCluster(nodeConfig.NodeIPv4Addr.IP, apis.AntreaAgentClusterMembershipPort, nodeConfig.Name, nodeInformer, ipPoolInformer, memberlist)
	if err != nil {
		return nil, err
	}

	// Make sure informers are running.
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	cache.WaitForCacheSync(stopCh, nodeInformer.Informer().HasSynced)
	cache.WaitForCacheSync(stopCh, ipPoolInformer.Informer().HasSynced)
	return &fakeCluster{
		cluster:   cluster,
		clientSet: clientset,
		crdClient: crdClient,
	}, nil
}

func createNode(cs *fake.Clientset, node *v1.Node) error {
	_, err := cs.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	return err
}

func createExternalIPPool(crdClient *fakeversioned.Clientset, eip *crdv1b1.ExternalIPPool) error {
	_, err := crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eip, metav1.CreateOptions{})
	return err
}

func TestCluster_Run(t *testing.T) {
	localNodeName := "localNodeName"
	testCases := []struct {
		name                     string
		egress                   *crdv1b1.Egress
		externalIPPool           *crdv1b1.ExternalIPPool
		localNode                *v1.Node
		expectEgressSelectResult bool
	}{
		{
			name: "Local Node matches ExternalIPPool nodeSelectors",
			egress: &crdv1b1.Egress{
				Spec: crdv1b1.EgressSpec{ExternalIPPool: "", EgressIP: "1.1.1.1"},
			},
			externalIPPool: &crdv1b1.ExternalIPPool{
				TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
				ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool"},
				Spec:       crdv1b1.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}},
			},
			localNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: localNodeName, Labels: map[string]string{"env": "pro"}},
				Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}},
			},
			expectEgressSelectResult: true,
		},
		{
			name: "Local Node does not match ExternalIPPool nodeSelectors",
			egress: &crdv1b1.Egress{
				Spec: crdv1b1.EgressSpec{ExternalIPPool: "", EgressIP: "1.1.1.1"},
			},
			externalIPPool: &crdv1b1.ExternalIPPool{
				TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
				ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool1"},
				Spec:       crdv1b1.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}},
			},
			localNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: localNodeName},
				Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}},
			},
			expectEgressSelectResult: false,
		},
	}
	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			stopCh := make(chan struct{})
			var wg sync.WaitGroup
			defer func() {
				// Make sure mock controller is closed after Run() finishes.
				close(stopCh)
				wg.Wait()
			}()

			nodeConfig := &config.NodeConfig{
				Name:         localNodeName,
				NodeIPv4Addr: &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 255)},
			}
			mockMemberlist := NewMockMemberlist(controller)
			fakeCluster, err := newFakeCluster(nodeConfig, stopCh, mockMemberlist, tCase.localNode)
			require.NoError(t, err, "New fake memberlist server error")

			mockMemberlist.EXPECT().Leave(time.Second)
			mockMemberlist.EXPECT().Shutdown()
			mockMemberlist.EXPECT().Members().Return([]*memberlist.Node{
				{Name: localNodeName},
			}).MinTimes(1)

			require.NoError(t, createExternalIPPool(fakeCluster.crdClient, tCase.externalIPPool))

			wg.Add(1)
			go func() {
				defer wg.Done()
				fakeCluster.cluster.Run(stopCh)
			}()

			assert.Eventually(t, func() bool {
				res, err := fakeCluster.cluster.ShouldSelectIP(tCase.egress.Spec.EgressIP, tCase.externalIPPool.Name)
				return err == nil && res == tCase.expectEgressSelectResult
			}, 1*time.Second, 100*time.Millisecond, "select Node result for Egress does not match")
		})
	}
}

func TestCluster_RunClusterEvents(t *testing.T) {
	controller := gomock.NewController(t)
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		// Make sure mock controller is closed after Run() finishes.
		close(stopCh)
		wg.Wait()
	}()

	nodeName := "localNodeName"
	nodeConfig := &config.NodeConfig{
		Name:         nodeName,
		NodeIPv4Addr: &net.IPNet{IP: net.IPv4(127, 0, 0, 1)},
	}
	localNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}}}
	fakeEIP1 := &crdv1b1.ExternalIPPool{
		TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool1"},
		Spec:       crdv1b1.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}},
	}
	fakeEgress1 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeEgress1", UID: "fakeUID1"},
		Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeEIP1.Name, EgressIP: "1.1.1.2"},
	}
	mockMemberlist := NewMockMemberlist(controller)
	fakeCluster, err := newFakeCluster(nodeConfig, stopCh, mockMemberlist, localNode)
	require.NoError(t, err, "New fake memberlist server error")
	// Test Cluster AddClusterEventHandler.
	fakeCluster.cluster.AddClusterEventHandler(func(objName string) {
		t.Logf("Detected cluster Node event, running fake handler, obj: %s", objName)
	})

	mockMemberlist.EXPECT().Leave(time.Second)
	mockMemberlist.EXPECT().Shutdown()
	mockMemberlist.EXPECT().Members().Return([]*memberlist.Node{
		{Name: nodeName},
	}).AnyTimes()
	require.NoError(t, createExternalIPPool(fakeCluster.crdClient, fakeEIP1))

	wg.Add(1)
	go func() {
		defer wg.Done()
		fakeCluster.cluster.Run(stopCh)
	}()

	// Test updating Node labels.
	testCasesUpdateNode := []struct {
		name                     string
		expectEgressSelectResult bool
		newNodeLabels            map[string]string
	}{
		{
			name:                     "Update Node with the same labels then local Node should not be selected",
			expectEgressSelectResult: false,
			newNodeLabels:            localNode.Labels,
		},
		{
			name:                     "Update Node with matched labels then local Node should be selected",
			expectEgressSelectResult: true,
			newNodeLabels:            map[string]string{"env": "pro", v1.LabelOSStable: "linux"},
		},
		{
			name:                     "Update Node with different but matched labels then local Node should be selected",
			expectEgressSelectResult: true,
			newNodeLabels:            map[string]string{"env": "pro", "env1": "test", v1.LabelOSStable: "linux"},
		},
		{
			name:                     "Update Node with not matched labels then local Node should not be selected",
			expectEgressSelectResult: false,
			newNodeLabels:            map[string]string{"env": "test", v1.LabelOSStable: "linux"},
		},
	}
	updateNode := func(node *v1.Node) {
		_, err := fakeCluster.clientSet.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
		require.NoError(t, err, "Update Node error")
	}
	for _, tCase := range testCasesUpdateNode {
		t.Run(tCase.name, func(t *testing.T) {
			newPod := localNode.DeepCopy()
			newPod.Labels = tCase.newNodeLabels
			updateNode(newPod)
			assert.Eventually(t, func() bool {
				res, err := fakeCluster.cluster.ShouldSelectIP(fakeEgress1.Spec.EgressIP, fakeEgress1.Spec.ExternalIPPool)
				return err == nil && res == tCase.expectEgressSelectResult
			}, 1*time.Second, 100*time.Millisecond, "select Node result for Egress does not match")
		})
	}

	// Test updating ExternalIPPool.
	newPod := localNode.DeepCopy()
	newPod.Labels = map[string]string{"env": "test", v1.LabelOSStable: "linux"}
	updateNode(newPod)
	testCasesUpdateEIP := []struct {
		name                     string
		expectEgressSelectResult bool
		newEIPnodeSelectors      metav1.LabelSelector
	}{
		{
			name:                     "Update ExternalIPPool with the same nodeSelector then local Node should not be selected",
			expectEgressSelectResult: false,
			newEIPnodeSelectors:      fakeEIP1.Spec.NodeSelector,
		},
		{
			name:                     "Update ExternalIPPool with the matched nodeSelector then local Node should be selected",
			expectEgressSelectResult: true,
			newEIPnodeSelectors:      metav1.LabelSelector{MatchLabels: map[string]string{"env": "test"}},
		},
		{
			name:                     "Update ExternalIPPool with nil nodeSelector then local Node should be selected",
			expectEgressSelectResult: true,
			newEIPnodeSelectors:      metav1.LabelSelector{},
		},
		{
			name:                     "Update ExternalIPPool refresh back then local Node should not be selected",
			expectEgressSelectResult: false,
			newEIPnodeSelectors:      fakeEIP1.Spec.NodeSelector,
		},
	}
	for _, tCase := range testCasesUpdateEIP {
		t.Run(tCase.name, func(t *testing.T) {
			fakeEIP1.Spec.NodeSelector = tCase.newEIPnodeSelectors
			_, err := fakeCluster.crdClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), fakeEIP1, metav1.UpdateOptions{})
			require.NoError(t, err, "Update ExternalIPPool error")
			assert.Eventually(t, func() bool {
				res, err := fakeCluster.cluster.ShouldSelectIP(fakeEgress1.Spec.EgressIP, fakeEgress1.Spec.ExternalIPPool)
				return err == nil && res == tCase.expectEgressSelectResult
			}, 1*time.Second, 100*time.Millisecond, "select Node result for Egress does not match")
		})
	}

	// Test creating new ExternalIPPool.
	fakeEIP2 := &crdv1b1.ExternalIPPool{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fakeExternalIPPool2",
		},
		Spec: crdv1b1.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "test"}}},
	}
	fakeEgressIP2 := "1.1.1.2"
	fakeEgress2 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeEgress2", UID: "fakeUID2"},
		Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeEIP2.Name, EgressIP: fakeEgressIP2},
	}
	require.NoError(t, createExternalIPPool(fakeCluster.crdClient, fakeEIP2))

	assertEgressSelectResult := func(egress *crdv1b1.Egress, expectedRes bool, hasSyncedErr bool) {
		assert.Eventuallyf(t, func() bool {
			res, err := fakeCluster.cluster.ShouldSelectIP(egress.Spec.EgressIP, egress.Spec.ExternalIPPool)
			if hasSyncedErr {
				return err != nil
			}
			return err == nil && res == expectedRes
		}, 1*time.Second, 100*time.Millisecond, "select Node result for Egress '%s' does not match", egress.Name)
	}
	assertEgressSelectResult(fakeEgress2, true, false)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test deleting ExternalIPPool.
	deleteExternalIPPool := func(eipName string) {
		err := fakeCluster.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), eipName, metav1.DeleteOptions{})
		require.NoError(t, err, "Delete ExternalIPPool error")
	}
	deleteExternalIPPool(fakeEIP2.Name)
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test Node update event.
	fakeCluster.cluster.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: "fakeNodeNameUpdate"}, Event: memberlist.NodeUpdate}
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test Node leave event.
	fakeCluster.cluster.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: localNode.Name}, Event: memberlist.NodeLeave}
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test Node leave event, Node not found.
	fakeCluster.cluster.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: "fakeNodeNameLeave"}, Event: memberlist.NodeLeave}
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test Node join event.
	fakeCluster.cluster.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: localNode.Name}, Event: memberlist.NodeJoin}
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test creating Node with invalid IP.
	fakeNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeNode0", Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "x"}}},
	}
	require.NoError(t, createNode(fakeCluster.clientSet, fakeNode))
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test deleting Node.
	deleteNode := func(node *v1.Node) {
		err := fakeCluster.clientSet.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Delete Node error")
	}
	deleteNode(newPod)
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	mockMemberlist.EXPECT().Join([]string{"1.1.1.1"})
	// Test creating Node with valid IP.
	fakeNode1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeNode1", Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "1.1.1.1"}}},
	}
	require.NoError(t, createNode(fakeCluster.clientSet, fakeNode1))
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)

	// Test creating Windows Node, which should be ignored.
	fakeWinNode1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeWinNode1", Labels: labelsWindowsOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "1.1.1.11"}}},
	}
	require.NoError(t, createNode(fakeCluster.clientSet, fakeWinNode1))
	assertEgressSelectResult(fakeEgress2, false, true)
	assertEgressSelectResult(fakeEgress1, false, false)
}

func genLocalNodeCluster(localNodeNme, eipName string, nodes []string) *Cluster {
	cluster := &Cluster{
		nodeName:          localNodeNme,
		consistentHashMap: make(map[string]*consistenthash.Map),
	}
	cluster.consistentHashMap[eipName] = NewNodeConsistentHashMap()
	cluster.consistentHashMap[eipName].Add(nodes...)
	return cluster
}

func genNodes(n int) []string {
	nodes := make([]string, n)
	for i := 0; i < n; i++ {
		nodes[i] = fmt.Sprintf("node-%d", i)
	}
	return nodes
}

// TestCluster_ConsistentHashDistribute test the distributions of Egresses in Nodes
func TestCluster_ConsistentHashDistribute(t *testing.T) {
	egressNum := 10
	testCases := []struct {
		name                  string
		nodes                 []string
		expectedDistributions map[string][]int
	}{
		{
			name:                  fmt.Sprintf("Assign owner Node for %d Egress", egressNum),
			nodes:                 []string{"node0", "node1", "node2"},
			expectedDistributions: map[string][]int{"node0": {1, 4, 9}, "node1": {0, 2, 5, 8}, "node2": {3, 6, 7}},
		},
		{
			// Failover, when Node failed, Egress should move to available Node.
			name:                  "A Node fail then Egress should move",
			nodes:                 []string{"node1", "node2"},
			expectedDistributions: map[string][]int{"node1": {0, 2, 4, 5, 8, 9}, "node2": {1, 3, 6, 7}},
		},
		{
			// Egress should move when Node added in cluster.
			name:                  "Add new Node then Egress should move",
			nodes:                 []string{"node0", "node1", "node2", "node3"},
			expectedDistributions: map[string][]int{"node0": {1, 4, 9}, "node1": {0, 5, 8}, "node2": {3, 6}, "node3": {2, 7}},
		},
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			actualDistribute := map[string][]int{}
			for _, node := range testC.nodes {
				fakeEIPName := "fakeExternalIPPool"
				fakeCluster := genLocalNodeCluster(node, fakeEIPName, testC.nodes)
				selectedNodes := []int{}
				for i := 0; i < egressNum; i++ {
					fakeEgress := &crdv1b1.Egress{
						ObjectMeta: metav1.ObjectMeta{Name: "fakeEgress"},
						Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeEIPName, EgressIP: fmt.Sprintf("10.1.1.%d", i)},
					}
					selected, err := fakeCluster.ShouldSelectIP(fakeEgress.Spec.EgressIP, fakeEgress.Spec.ExternalIPPool)
					assert.NoError(t, err)
					if selected {
						selectedNodes = append(selectedNodes, i)
					}
				}
				actualDistribute[node] = selectedNodes
				t.Logf("Distributions of Egresses in Node %s: %#v", node, selectedNodes)
			}
			assert.Equal(t, testC.expectedDistributions, actualDistribute, "Egress distributions not match")
		})
	}
}

func TestCluster_ShouldSelectEgress(t *testing.T) {
	testCases := []struct {
		name         string
		nodeNum      int
		egressIP     string
		expectedNode string
	}{
		{
			name:         "Select Node from 0 Nodes",
			nodeNum:      0,
			egressIP:     "1.1.1.1",
			expectedNode: "",
		},
		{
			name:         "Select Node from 1 Nodes",
			nodeNum:      1,
			egressIP:     "1.1.1.1",
			expectedNode: "node-0",
		},
		{
			name:         "Select Node from 3 Nodes",
			nodeNum:      3,
			egressIP:     "1.1.1.1",
			expectedNode: "node-1",
		},
		{
			name:         "Select Node from 10 Nodes",
			nodeNum:      10,
			egressIP:     "1.1.1.1",
			expectedNode: "node-1",
		},
		{
			name:         "Select Node from 100 Nodes",
			nodeNum:      100,
			egressIP:     "1.1.1.1",
			expectedNode: "node-79",
		},
	}
	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			fakeEIPName := "fakeExternalIPPool"
			fakeEgress := &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "fakeEgress"},
				Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeEIPName, EgressIP: tCase.egressIP},
			}
			consistentHashMap := NewNodeConsistentHashMap()
			consistentHashMap.Add(genNodes(tCase.nodeNum)...)

			fakeCluster := &Cluster{
				consistentHashMap: map[string]*consistenthash.Map{fakeEIPName: consistentHashMap},
			}

			for i := 0; i < tCase.nodeNum; i++ {
				node := fmt.Sprintf("node-%d", i)
				fakeCluster.nodeName = node
				selected, err := fakeCluster.ShouldSelectIP(fakeEgress.Spec.EgressIP, fakeEgress.Spec.ExternalIPPool)
				require.NoError(t, err)
				assert.Equal(t, node == tCase.expectedNode, selected, "Selected Node for Egress not match")
			}
		})
	}
}

func TestCluster_SelectNodeForIP(t *testing.T) {
	testCases := []struct {
		name         string
		nodeNum      int
		ip           string
		expectedNode string
		filters      []func(string) bool
	}{
		{
			name:         "Select Node from 0 Nodes",
			nodeNum:      0,
			ip:           "1.1.1.1",
			expectedNode: "",
			filters:      nil,
		},
		{
			name:         "Select Node from 1 Nodes",
			nodeNum:      1,
			ip:           "1.1.1.1",
			expectedNode: "node-0",
			filters:      nil,
		},
		{
			name:         "Select Node from 3 Nodes",
			nodeNum:      3,
			ip:           "1.1.1.1",
			expectedNode: "node-1",
			filters:      nil,
		},
		{
			name:         "Select Node from 10 Nodes",
			nodeNum:      10,
			ip:           "1.1.1.1",
			expectedNode: "node-1",
			filters:      nil,
		},
		{
			name:         "Select Node from 100 Nodes",
			nodeNum:      100,
			ip:           "1.1.1.1",
			expectedNode: "node-79",
			filters:      nil,
		},
	}
	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			fakeEIPName := "fakeExternalIPPool"
			consistentHashMap := NewNodeConsistentHashMap()
			consistentHashMap.Add(genNodes(tCase.nodeNum)...)

			fakeCluster := &Cluster{
				consistentHashMap: map[string]*consistenthash.Map{fakeEIPName: consistentHashMap},
			}

			for i := 0; i < tCase.nodeNum; i++ {
				node := fmt.Sprintf("node-%d", i)
				fakeCluster.nodeName = node
				selected, err := fakeCluster.ShouldSelectIP(tCase.ip, fakeEIPName, tCase.filters...)
				require.NoError(t, err)
				assert.Equal(t, node == tCase.expectedNode, selected, "Selected Node not match")
			}
		})
	}
}

// BenchmarkCluster_ShouldSelect
// BenchmarkCluster_ShouldSelect/Select_Node_from_10000_alive_nodes-nodeSelectedForEgress
// BenchmarkCluster_ShouldSelect/Select_Node_from_10000_alive_nodes-nodeSelectedForEgress-16         	 9190818	       128 ns/op
// BenchmarkCluster_ShouldSelect/Select_Node_from_1000_alive_nodes-nodeSelectedForEgress
// BenchmarkCluster_ShouldSelect/Select_Node_from_1000_alive_nodes-nodeSelectedForEgress-16          	 9474440	       125 ns/op
// PASS
func BenchmarkCluster_ShouldSelect(b *testing.B) {
	benchmarkCases := []struct {
		name  string
		nodes []string
	}{
		{
			name:  "Select Node from 10000 alive Nodes",
			nodes: genNodes(10000),
		},
		{
			name:  "Select Node from 1000 alive Nodes",
			nodes: genNodes(1000),
		},
	}

	for _, bc := range benchmarkCases {
		fakeEIPName := "fakeExternalIPPool"
		fakeEgress := &crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "fakeEgress"},
			Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeEIPName, EgressIP: "1.1.1.1"},
		}
		fakeCluster := genLocalNodeCluster("fakeLocalNodeName", fakeEIPName, bc.nodes)
		b.Run(fmt.Sprintf("%s-nodeSelectedForEgress", bc.name), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fakeCluster.ShouldSelectIP(fakeEgress.Spec.EgressIP, fakeEgress.Spec.ExternalIPPool)
			}
		})
	}
}

func TestCluster_RejoinNodes(t *testing.T) {
	localNodeConfig := &config.NodeConfig{
		Name:         "node1",
		NodeIPv4Addr: ip.MustParseCIDR("10.0.0.1/24"),
	}
	node1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.1"}}},
	}
	node2 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.2"}}},
	}
	node3 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node3", Labels: labelsLinuxOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.3"}}},
	}
	winNode1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "winnode1", Labels: labelsWindowsOS},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.11"}}},
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	controller := gomock.NewController(t)
	mockMemberlist := NewMockMemberlist(controller)
	mockMemberlist.EXPECT().Join([]string{"10.0.0.2"})
	mockMemberlist.EXPECT().Join([]string{"10.0.0.3"})
	fakeCluster, _ := newFakeCluster(localNodeConfig, stopCh, mockMemberlist, node1, node2, node3, winNode1)

	mockMemberlist.EXPECT().Members().Return([]*memberlist.Node{
		{Name: "node1"},
		{Name: "node2"},
	})
	mockMemberlist.EXPECT().Join([]string{"10.0.0.3"})
	fakeCluster.cluster.RejoinNodes()

	mockMemberlist.EXPECT().Members().Return([]*memberlist.Node{
		{Name: "node1"},
		{Name: "node3"},
	})
	mockMemberlist.EXPECT().Join([]string{"10.0.0.2"})
	fakeCluster.cluster.RejoinNodes()
}
