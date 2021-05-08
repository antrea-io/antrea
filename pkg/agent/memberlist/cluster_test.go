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
	"crypto/rand"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

func TestCluster_Run(t *testing.T) {
	localNodeName := "test_memberlist_node"
	nodeConfig := &config.NodeConfig{
		Name:       localNodeName,
		NodeIPAddr: &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 255)},
	}

	localNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: localNodeName},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}},
	}

	eip := &crdv1a2.ExternalIPPool{
		TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "fake_ip_pool"},
		Spec:       crdv1a2.ExternalIPPoolSpec{},
	}
	eip1 := &crdv1a2.ExternalIPPool{
		TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "fake_ip_pool1"},
		Spec:       crdv1a2.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}},
	}

	fakeEgressIP := "1.1.1.1"
	eg := &crdv1a2.Egress{
		Spec: crdv1a2.EgressSpec{ExternalIPPool: eip.Name, EgressIP: fakeEgressIP},
	}

	testCases := []struct {
		name                     string
		egress                   *crdv1a2.Egress
		externalIPPool           *crdv1a2.ExternalIPPool
		expectEgressSelectResult bool
	}{
		{
			name:                     "local Node matches ExternalIPPool nodeSelectors",
			egress:                   eg,
			externalIPPool:           eip,
			expectEgressSelectResult: true,
		},
		{
			name:                     "local Node not match ExternalIPPool nodeSelectors",
			egress:                   eg,
			externalIPPool:           eip1,
			expectEgressSelectResult: false,
		},
	}
	for i, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			port := apis.AntreaAgentClusterPort + i

			cs := fake.NewSimpleClientset()
			informerFactory := informers.NewSharedInformerFactory(cs, 0)

			nodeInformer := informerFactory.Core().V1().Nodes()

			crdClient := fakeversioned.NewSimpleClientset([]runtime.Object{}...)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
			ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

			createAndCheckNode := func(node *v1.Node) {
				_, err := cs.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Add Node error: %v", err)
				}
				assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
					newNode, _ := cs.CoreV1().Nodes().Get(context.TODO(), node.Name, metav1.GetOptions{})
					return reflect.DeepEqual(newNode, node), nil
				}))
			}

			createAndCheckEIP := func(eip *crdv1a2.ExternalIPPool) {
				_, err := crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Create ExternalIPPool error: %v", err)
				}
				assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
					newEIP, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), eip.Name, metav1.GetOptions{})
					return reflect.DeepEqual(eip, newEIP), nil
				}))
			}

			s, err := NewCluster(port, nodeConfig.NodeIPAddr.IP, nodeConfig.Name, nodeInformer, ipPoolInformer)
			if err != nil {
				t.Fatalf("New memberlist server error: %v", err)
			}

			// Make sure informers are running.
			informerFactory.Start(stopCh)
			crdInformerFactory.Start(stopCh)

			cache.WaitForCacheSync(stopCh, nodeInformer.Informer().HasSynced)
			cache.WaitForCacheSync(stopCh, ipPoolInformer.Informer().HasSynced)

			createAndCheckEIP(tCase.externalIPPool)
			createAndCheckNode(localNode)

			go s.Run(stopCh)

			assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
				eip, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), tCase.externalIPPool.Name, metav1.GetOptions{})
				return reflect.DeepEqual(eip, tCase.externalIPPool), nil
			}))

			res, _ := s.ShouldSelectEgress(tCase.egress)
			allMembers, _ := s.allClusterMembers()
			assert.Equal(t, 1, len(allMembers), "expected Node member num is 1")
			assert.Equal(t, 1, s.mList.NumMembers(), "expected alive Node num is 1")
			assert.Equal(t, tCase.expectEgressSelectResult, res, "select Node for Egress result not match")
		})
	}
}

func TestCluster_RunClusterEvents(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentClusterPort + 10
	nodeName := "local_node_name"
	nodeConfig := &config.NodeConfig{
		Name:       nodeName,
		NodeIPAddr: &net.IPNet{IP: net.IPv4(127, 0, 0, 1)},
	}

	cs := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(cs, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	crdClient := fakeversioned.NewSimpleClientset([]runtime.Object{}...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

	s, err := NewCluster(port, nodeConfig.NodeIPAddr.IP, nodeConfig.Name, nodeInformer, ipPoolInformer)
	if err != nil {
		t.Fatalf("New memberlist server error: %v", err)
	}

	// Make sure informers are running.
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	cache.WaitForCacheSync(stopCh, nodeInformer.Informer().HasSynced)
	cache.WaitForCacheSync(stopCh, ipPoolInformer.Informer().HasSynced)

	createAndCheckNode := func(node *v1.Node) {
		_, err := cs.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Add Node error: %v", err)
		}
		assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
			newNode, _ := cs.CoreV1().Nodes().Get(context.TODO(), node.Name, metav1.GetOptions{})
			return reflect.DeepEqual(newNode, node), nil
		}))
	}
	createAndCheckEIP := func(eip *crdv1a2.ExternalIPPool) {
		_, err := crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Create ExternalIPPool error: %v", err)
		}
		assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
			newEIP, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), eip.Name, metav1.GetOptions{})
			return reflect.DeepEqual(eip, newEIP), nil
		}))
	}
	localNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}}}
	eip := &crdv1a2.ExternalIPPool{
		TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "fake_ip_pool"},
		Spec:       crdv1a2.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}},
	}
	createAndCheckNode(localNode)
	createAndCheckEIP(eip)

	s.AddClusterEventHandler(func(objName string) {
		t.Logf("Detected cluster Node event, running fake handler, obj: %s", objName)
	})

	go s.Run(stopCh)

	assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
		return s.nodeListerSynced() && s.externalIPPoolInformerHasSynced(), nil
	}))

	fakeEgressIP := "1.1.1.2"
	eg := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "testClusterEgress", UID: "fakeUID"},
		Spec:       crdv1a2.EgressSpec{ExternalIPPool: eip.Name, EgressIP: fakeEgressIP},
	}
	testCaseNodeUpdate := []struct {
		name                     string
		expectEgressSelectResult bool
		newNodeLabels            map[string]string
		egress                   *crdv1a2.Egress
	}{
		{
			name:                     "update Node with the same labels then local Node should not be selected",
			expectEgressSelectResult: false,
			newNodeLabels:            localNode.Labels,
			egress:                   eg,
		},
		{
			name:                     "update Node with matched labels then local Node should be selected",
			expectEgressSelectResult: true,
			newNodeLabels:            map[string]string{"env": "pro"},
			egress:                   eg,
		},
		{
			name:                     "update Node with different but matched labels then local Node should be selected",
			expectEgressSelectResult: true,
			newNodeLabels:            map[string]string{"env": "pro", "env1": "test"},
			egress:                   eg,
		},
		{
			name:                     "update Node with not matched labels then should not be selected",
			expectEgressSelectResult: false,
			newNodeLabels:            map[string]string{"env": "test"},
			egress:                   eg,
		},
	}
	updateAndCheckNode := func(node *v1.Node) {
		_, err = cs.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("Update Node error: %v", err)
		}
		assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
			newNode, _ := cs.CoreV1().Nodes().Get(context.TODO(), node.Name, metav1.GetOptions{})
			return reflect.DeepEqual(node, newNode), nil
		}))
	}
	for _, tCase := range testCaseNodeUpdate {
		t.Run(tCase.name, func(t *testing.T) {
			localNode.Labels = tCase.newNodeLabels
			updateAndCheckNode(localNode)
			res, _ := s.ShouldSelectEgress(tCase.egress)
			assert.Equal(t, tCase.expectEgressSelectResult, res, "select Node for Egress result not match")
		})
	}

	// Test updating ExternalIPPool.
	localNode.Labels = map[string]string{"env": "test"}
	updateAndCheckNode(localNode)
	testCaseEIPEvecnts := []struct {
		name                     string
		expectEgressSelectResult bool
		newEIPnodeSelectors      metav1.LabelSelector
	}{
		{
			name:                     "update ExternalIPPool with the same nodeSelector then local Node should not selected",
			expectEgressSelectResult: false,
			newEIPnodeSelectors:      eip.Spec.NodeSelector,
		},
		{
			name:                     "update ExternalIPPool with the matched nodeSelector then local Node should selected",
			expectEgressSelectResult: true,
			newEIPnodeSelectors:      metav1.LabelSelector{MatchLabels: map[string]string{"env": "test"}},
		},
		{
			name:                     "update ExternalIPPool with nil nodeSelector then local Node should selected",
			expectEgressSelectResult: true,
			newEIPnodeSelectors:      metav1.LabelSelector{},
		},
		{
			name:                     "update ExternalIPPool refresh back then local Node should not selected",
			expectEgressSelectResult: false,
			newEIPnodeSelectors:      eip.Spec.NodeSelector,
		},
	}
	for _, tCase := range testCaseEIPEvecnts {
		t.Run(tCase.name, func(t *testing.T) {
			eip.Spec.NodeSelector = tCase.newEIPnodeSelectors
			_, err := crdClient.CrdV1alpha2().ExternalIPPools().Update(context.TODO(), eip, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Update ExternalIPPool error: %v", err)
			}
			assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
				newEIP, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), eip.Name, metav1.GetOptions{})
				return reflect.DeepEqual(eip, newEIP), nil
			}))
			res, _ := s.ShouldSelectEgress(eg)
			assert.Equal(t, tCase.expectEgressSelectResult, res, "select Node for Egress result not match")
		})
	}

	eipEnvTest := &crdv1a2.ExternalIPPool{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "eipEnvTest",
		},
		Spec: crdv1a2.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "test"}}},
	}
	// Test creating new ExternalIPPool.
	egEnvTest := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "testClusterEgress1", UID: "fakeUID1"},
		Spec:       crdv1a2.EgressSpec{ExternalIPPool: eipEnvTest.Name, EgressIP: fakeEgressIP},
	}
	createAndCheckEIP(eipEnvTest)
	assertEgressSelectResult := func(egress *crdv1a2.Egress, expectedRes bool) {
		res, _ := s.ShouldSelectEgress(egress)
		assert.Equal(t, expectedRes, res, "select Node for Egress result not match")
	}
	assertEgressSelectResult(egEnvTest, true)
	assertEgressSelectResult(eg, false)

	// Test deleting ExternalIPPool.
	deleteAndCheckEIP := func(eipName string) {
		err := crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), eipName, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("Delete ExternalIPPool error: %v", err)
		}
		assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
			newEIP, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), eipName, metav1.GetOptions{})
			return nil == newEIP, nil
		}))
	}
	// ExternalIPPool nodeSelector is nil.
	deleteAndCheckEIP(eipEnvTest.Name)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test Node update events.
	s.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: "test-update-node"}, Event: memberlist.NodeUpdate}
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test Node leave events.
	s.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: localNode.Name}, Event: memberlist.NodeLeave}
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test Node leave event, Node not found.
	s.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: "test-update-node"}, Event: memberlist.NodeLeave}
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test Node join event.
	s.nodeEventsCh <- memberlist.NodeEvent{Node: &memberlist.Node{Name: localNode.Name}, Event: memberlist.NodeJoin}
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test creating Node with invalid IP.
	fakeNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-node0"},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "x"}}},
	}
	createAndCheckNode(fakeNode)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test deleting Node
	deleteAndCheckNode := func(node *v1.Node) {
		err := cs.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("Delete Node error: %v", err)
		}
		assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
			delNode, _ := cs.CoreV1().Nodes().Get(context.TODO(), node.Name, metav1.GetOptions{})
			return delNode == nil, nil
		}))
	}
	deleteAndCheckNode(localNode)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test creating Node with valid IP.
	fakeNode1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-node1"},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "1.1.1.1"}}},
	}
	createAndCheckNode(fakeNode1)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)
}

func TestCluster_ShouldSelectNodeFailedOrAddedByConsistentHash(t *testing.T) {
	const egressNum = 100
	expectEgressSeqSum := func(n int) int {
		count := 0
		for i := 0; i < n; i++ {
			count += i
		}
		return count
	}(egressNum)

	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}

	nodes := genNodes(12)
	testCases := []struct {
		name           string
		nodes          []string
		consistentHash *consistenthash.Map
	}{
		{
			name:           fmt.Sprintf("assign owner Node for %d Egress", egressNum),
			nodes:          nodes[:10],
			consistentHash: consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			// Failover, when Node failed, Egress should move to available Node.
			name:           "a Node fail then Egress should move",
			nodes:          nodes[1:10],
			consistentHash: consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			// Egress should move when Node added in cluster.
			name:           "add new Node then Egress should move",
			nodes:          nodes[:11],
			consistentHash: consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			name:           fmt.Sprintf("recover to %d nodes", 10),
			nodes:          nodes[:10],
			consistentHash: consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
	}

	nodeSelectedForEgress := func(consistentHash *consistenthash.Map, egressName, nodeName string) bool {
		return consistentHash.Get(egressName) == nodeName
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			nodes := testC.nodes
			testC.consistentHash.Add(nodes...)
			nodeEgress := make(map[string][]string, len(nodes))
			hitCount := 0
			seqSum := 0
			for i := 0; i < egressNum; i++ {
				egressName := fmt.Sprintf("%d", i)
				for j := range nodes {
					localNode := nodes[j]
					if nodeSelectedForEgress(testC.consistentHash, egressName, localNode) {
						nodeEgress[localNode] = append(nodeEgress[localNode], egressName)
						hitCount++
						seqSum += i
					}
				}
			}
			assert.Equal(t, expectEgressSeqSum, seqSum, "Egress seq")
			for _, node := range nodes {
				t.Logf("Node (%s) Egress: %#v", node, nodeEgress[node])
			}
			assert.Equal(t, egressNum, hitCount, "Egress total num should be 30")
		})
	}
}

// replicas = 1
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-3-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 1
// cluster_test.go:612: Node: node2, egressNum: 1
// cluster_test.go:612: Node: node3, egressNum: 1
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 4
// cluster_test.go:612: Node: node2, egressNum: 2
// cluster_test.go:612: Node: node3, egressNum: 4
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-100-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 44
// cluster_test.go:612: Node: node2, egressNum: 43
// cluster_test.go:612: Node: node3, egressNum: 13
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-1000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 474
// cluster_test.go:612: Node: node2, egressNum: 408
// cluster_test.go:612: Node: node3, egressNum: 118
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 5284
// cluster_test.go:612: Node: node2, egressNum: 3390
// cluster_test.go:612: Node: node3, egressNum: 1326
// --- PASS: TestCluster_ShouldSelectByConsistentHash (0.09s)

// replicas = 3
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-3-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 0
// cluster_test.go:612: Node: node2, egressNum: 2
// cluster_test.go:612: Node: node3, egressNum: 1
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 1
// cluster_test.go:612: Node: node2, egressNum: 5
// cluster_test.go:612: Node: node3, egressNum: 4
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-100-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 30
// cluster_test.go:612: Node: node2, egressNum: 33
// cluster_test.go:612: Node: node3, egressNum: 37
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-1000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 348
// cluster_test.go:612: Node: node2, egressNum: 317
// cluster_test.go:612: Node: node3, egressNum: 335
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 3318
// cluster_test.go:612: Node: node2, egressNum: 3469
// cluster_test.go:612: Node: node3, egressNum: 3213
// --- PASS: TestCluster_ShouldSelectByConsistentHash (0.10s)

// replicas = 50
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-3-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 1
// cluster_test.go:612: Node: node2, egressNum: 2
// cluster_test.go:612: Node: node3, egressNum: 0
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 1
// cluster_test.go:612: Node: node2, egressNum: 4
// cluster_test.go:612: Node: node3, egressNum: 5
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-100-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 30
// cluster_test.go:612: Node: node2, egressNum: 32
// cluster_test.go:612: Node: node3, egressNum: 38
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-1000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 345
// cluster_test.go:612: Node: node2, egressNum: 297
// cluster_test.go:612: Node: node3, egressNum: 358
// === RUN   TestCluster_ShouldSelectByConsistentHash/select_node_from_alive_nodes-10000-Egresses
// === CONT  TestCluster_ShouldSelectByConsistentHash
// cluster_test.go:612: Node: node1, egressNum: 3437
// cluster_test.go:612: Node: node2, egressNum: 2930
// cluster_test.go:612: Node: node3, egressNum: 3633
// --- PASS: TestCluster_ShouldSelectByConsistentHash (0.10s)
// https://github.com/golang/groupcache/issues/29
func TestCluster_ShouldSelectEgress(t *testing.T) {
	nodes := []string{"node1", "node2", "node3"}
	consistentHash := consistenthash.New(defaultVirtualNodeReplicas, nil)
	consistentHash.Add(nodes...)

	nodeSelectedForEgress := func(consistentHash *consistenthash.Map, egressName, nodeName string) bool {
		return consistentHash.Get(egressName) == nodeName
	}

	checkNum := func(count int, localNode string) int {
		totalNum := 0
		for i := 0; i < count; i++ {
			egressName := fmt.Sprintf("egress-%d", i)
			if nodeSelectedForEgress(consistentHash, egressName, localNode) {
				totalNum++
			}
		}
		return totalNum
	}

	checkSum := func(egressNum int) int {
		count := 0
		for _, node := range nodes {
			num := checkNum(egressNum, node)
			count += num
			t.Logf("Node: %s, egressNum: %d", node, num)
		}
		return count
	}

	testCases := []struct {
		name      string
		egressNum int
	}{
		{
			name:      "select Node from alive nodes",
			egressNum: 3,
		},
		{
			name:      "select Node from alive nodes",
			egressNum: 10,
		},
		{
			name:      "select Node from alive nodes",
			egressNum: 100,
		},
		{
			name:      "select Node from alive nodes",
			egressNum: 1000,
		},
		{
			name:      "select Node from alive nodes",
			egressNum: 10000,
		},
	}
	for _, tCase := range testCases {
		t.Run(fmt.Sprintf("%s-%d-Egresses", tCase.name, tCase.egressNum), func(t *testing.T) {
			assert.Equal(t, tCase.egressNum, checkSum(tCase.egressNum))
		})
	}
}

// BenchmarkCluster_ShouldSelect
// BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes
// BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes-16         	12263878	        95.5 ns/op
// BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes
// BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes-16          	13036746	       103 ns/op
// BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes
// BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes-16           	14923483	        77.5 ns/op
func BenchmarkCluster_ShouldSelect(b *testing.B) {
	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}
	nodeSelectedForEgress := func(consistentHash *consistenthash.Map, egressName, nodeName string) bool {
		return consistentHash.Get(egressName) == nodeName
	}

	benchmarkCases := []struct {
		name       string
		nodes      []string
		egressName string
		localNode  string
	}{
		{
			name:       "select Node from 10000 alive nodes",
			nodes:      genNodes(10000),
			egressName: "egress-10",
			localNode:  "node-10",
		},
		{
			name:       "select Node from 1000 alive nodes",
			nodes:      genNodes(1024),
			egressName: "egress-10",
			localNode:  "node-10",
		},
		{
			name:       "select Node from 100 alive nodes",
			nodes:      genNodes(128),
			egressName: "egress-10",
			localNode:  "node-10",
		},
		{
			name:       "select Node from 10 alive nodes",
			nodes:      genNodes(8),
			egressName: "egress-10",
			localNode:  "node-10",
		},
	}

	for i := range benchmarkCases {
		bc := benchmarkCases[i]
		b.Run(fmt.Sprintf("%s-nodeSelectedForEgress", bc.name), func(b *testing.B) {
			b.ResetTimer()
			consistentHash := consistenthash.New(defaultVirtualNodeReplicas, nil)
			consistentHash.Add(bc.nodes...)
			for i := 0; i < b.N; i++ {
				nodeSelectedForEgress(consistentHash, bc.egressName, bc.localNode)
			}
		})
	}
}

func genRandomStr(num int) string {
	buf := make([]byte, num)
	_, err := rand.Read(buf)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", buf)
}

func TestCluster_ShouldSelect(t *testing.T) {
	nodes := []string{"node1"}

	genLocalNodeCluster := func(nodeNme string) *Cluster {
		cluster := &Cluster{
			mList:             &memberlist.Memberlist{},
			nodeName:          nodeNme,
			consistentHashMap: make(map[string]*consistenthash.Map),
		}
		return cluster
	}

	node1Cluster := genLocalNodeCluster("node1")
	node1Cluster.consistentHashMap["default"] = consistenthash.New(defaultVirtualNodeReplicas, nil)
	node1Cluster.consistentHashMap["default"].Add(nodes...)

	egressNum := 3
	hitCount := 0
	for i := 0; i < egressNum; i++ {
		egressName := fmt.Sprintf("%s-%d", genRandomStr(10), i)
		if node1Cluster.consistentHashMap["default"].Get(egressName) == nodes[0] {
			hitCount++
		}
	}
	assert.Equal(t, egressNum, hitCount, "Egress total num should be equal")
}
