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

			port := apis.AntreaAgentClusterMembershipPort + i

			cs := fake.NewSimpleClientset()
			informerFactory := informers.NewSharedInformerFactory(cs, 0)

			nodeInformer := informerFactory.Core().V1().Nodes()

			crdClient := fakeversioned.NewSimpleClientset([]runtime.Object{}...)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
			ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

			createNode := func(node *v1.Node) {
				_, err := cs.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Add Node error: %v", err)
				}
			}

			createAndCheckEIP := func(eip *crdv1a2.ExternalIPPool) {
				_, err := crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Create ExternalIPPool error: %v", err)
				}
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
			createNode(localNode)

			go s.Run(stopCh)

			assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
				eip, _ := crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), tCase.externalIPPool.Name, metav1.GetOptions{})
				return reflect.DeepEqual(eip, tCase.externalIPPool), nil
			}))

			res, _ := s.ShouldSelectEgress(tCase.egress)
			allMembers, err := s.allClusterMembers()
			assert.NoError(t, err)
			assert.Equal(t, 1, len(allMembers), "expected Node member num is 1")
			assert.Equal(t, 1, s.mList.NumMembers(), "expected alive Node num is 1")
			assert.Equal(t, tCase.expectEgressSelectResult, res, "select Node for Egress result not match")
		})
	}
}

func TestCluster_RunClusterEvents(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentClusterMembershipPort + 10
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

	createNode := func(node *v1.Node) {
		_, err := cs.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Add Node error: %v", err)
		}
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
	createNode(localNode)
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
	createNode(fakeNode)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test deleting Node
	deleteAndCheckNode := func(node *v1.Node) {
		err := cs.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("Delete Node error: %v", err)
		}
	}
	deleteAndCheckNode(localNode)
	assertEgressSelectResult(egEnvTest, false)
	assertEgressSelectResult(eg, false)

	// Test creating Node with valid IP.
	fakeNode1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-node1"},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "1.1.1.1"}}},
	}
	createNode(fakeNode1)
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

func TestCluster_ShouldSelectEgress(t *testing.T) {
	testCases := []struct {
		name         string
		nodeNum      int
		egressIP     string
		expectedNode string
	}{
		{
			name:         "select Node from alive nodes",
			nodeNum:      0,
			egressIP:     "1.1.1.1",
			expectedNode: "",
		},
		{
			name:         "select Node from alive nodes",
			nodeNum:      1,
			egressIP:     "1.1.1.1",
			expectedNode: "node-0",
		},
		{
			name:         "select Node from alive nodes",
			nodeNum:      3,
			egressIP:     "1.1.1.1",
			expectedNode: "node-1",
		},
		{
			name:         "select Node from alive nodes",
			nodeNum:      10,
			egressIP:     "1.1.1.1",
			expectedNode: "node-1",
		},
		{
			name:         "select Node from alive nodes",
			nodeNum:      100,
			egressIP:     "1.1.1.1",
			expectedNode: "node-79",
		},
	}
	for _, tCase := range testCases {
		t.Run(fmt.Sprintf("%s-nodeNum-%d", tCase.name, tCase.nodeNum), func(t *testing.T) {
			genLocalNodeCluster := func(nodeNme string) *Cluster {
				cluster := &Cluster{
					mList:             &memberlist.Memberlist{},
					nodeName:          nodeNme,
					consistentHashMap: make(map[string]*consistenthash.Map),
				}
				return cluster
			}

			genNodes := func(n int) []string {
				nodes := make([]string, n)
				for i := 0; i < n; i++ {
					nodes[i] = fmt.Sprintf("node-%d", i)
				}
				return nodes
			}

			fakeEgressName := "fake-Egress-Name"
			fakeEIPName := "fake-EIP-Name"
			fakeEgress := &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: fakeEgressName},
				Spec:       crdv1a2.EgressSpec{ExternalIPPool: fakeEIPName, EgressIP: tCase.egressIP},
			}

			if tCase.nodeNum == 0 {
				fakeCluster := genLocalNodeCluster("local-Node-Name")
				fakeCluster.consistentHashMap[fakeEIPName] = consistenthash.New(defaultVirtualNodeReplicas, nil)
				selected, err := fakeCluster.ShouldSelectEgress(fakeEgress)
				assert.NoError(t, err)
				assert.Equal(t, false, selected, "Select Node for Egress not match")
			} else {
				nodes := genNodes(tCase.nodeNum)
				var actualNodes []string
				for _, node := range nodes {
					fakeCluster := genLocalNodeCluster(node)
					fakeCluster.consistentHashMap[fakeEIPName] = consistenthash.New(defaultVirtualNodeReplicas, nil)
					fakeCluster.consistentHashMap[fakeEIPName].Add(nodes...)
					selected, err := fakeCluster.ShouldSelectEgress(fakeEgress)
					assert.NoError(t, err)
					if selected {
						actualNodes = append(actualNodes, node)
					}
				}
				assert.Equal(t, 1, len(actualNodes), "Selected Node num for Egress not match")
				assert.Equal(t, []string{tCase.expectedNode}, actualNodes, "Select Node for Egress not match")
			}
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
