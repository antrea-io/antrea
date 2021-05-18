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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

const testDefaultInterval = 1 * time.Second

func hitNode(nodes []string, name, myNode string) bool {
	if len(nodes) == 0 {
		return false
	}
	minNode := sha256.Sum256([]byte(nodes[0] + "#" + name))
	hitNode := nodes[0]
	for i := 1; i < len(nodes); i++ {
		hi := sha256.Sum256([]byte(nodes[i] + "#" + name))
		if bytes.Compare(hi[:], minNode[:]) < 0 {
			minNode = hi
			hitNode = nodes[i]
		}
	}
	return hitNode == myNode
}

func TestNewCluster(t *testing.T) {
	// init cluster with a exterlIPPool without node selector(nil)
	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentClusterPort
	nodeName := "test_memberlist_node"
	nodeConfig := &config.NodeConfig{
		Name: nodeName,
		NodeIPAddr: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	localNode0 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "127.0.0.1"}}}}

	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()

	exterlIPPool := crdv1a2.ExternalIPPool{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake_ip_pool",
		},
		Spec: crdv1a2.ExternalIPPoolSpec{},
	}
	crdClient := fakeversioned.NewSimpleClientset([]runtime.Object{&exterlIPPool}...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), localNode0, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	node1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test_node0",
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.11"}}}}

	s, err := NewCluster(port, nodeInformer, nodeConfig, ipPoolInformer)
	if err != nil {
		t.Fatalf("New memberlist server error: %v", err)
	}

	// Make sure informers are running.
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	cache.WaitForCacheSync(stopCh, nodeInformer.Informer().HasSynced)
	cache.WaitForCacheSync(stopCh, ipPoolInformer.Informer().HasSynced)

	s.AddClusterNodeEventHandler(func(nodeName string, added bool) {
		t.Logf("notified node %s added (%t) node event handler", nodeName, added)
	})

	go s.Run(stopCh)

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	node2 := &v1.Node{Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.12"}}}}

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node2, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 3, s.memberNum(), "expected node member num is 3")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	s.nodeEventsCh <- memberlist.NodeEvent{
		Node:  &memberlist.Node{Name: "testleaveNodeName"},
		Event: memberlist.NodeLeave,
	}

	s.nodeEventsCh <- memberlist.NodeEvent{
		Node:  &memberlist.Node{Name: "testleaveNodeName", State: 0},
		Event: memberlist.NodeUpdate,
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 3, s.memberNum(), "expected node member num is 3")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// update exterlIPPool with node selector and test join node in cluster
	exterlIPPool.Spec.NodeSelector = metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}
	_, err = crdClient.CrdV1alpha2().ExternalIPPools().Update(context.TODO(), &exterlIPPool, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Create exterlIPPool error:%v", err)
	}

	exterlIPPool1 := crdv1a2.ExternalIPPool{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "fake_ip_pool1"},
		Spec: crdv1a2.ExternalIPPoolSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}},
		},
	}

	_, err = crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), &exterlIPPool1, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create exterlIPPool error:%v", err)
	}

	node3 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test_node2",
			Labels: map[string]string{"env": "pro"},
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.13"}}}}

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node3, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)
	// update externalIPPool and local node should leave
	assert.Equal(t, 4, s.memberNum(), "expected node member num is 4")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 0")

	// update external IPPool and local node will join
	exterlIPPool.Spec.NodeSelector = metav1.LabelSelector{}
	_, err = crdClient.CrdV1alpha2().ExternalIPPools().Update(context.TODO(), &exterlIPPool, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Create exterlIPPool error:%v", err)
	}

	time.Sleep(testDefaultInterval)
	assert.Equal(t, 4, s.memberNum(), "expected node member num is 4")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// delete external IPPool and local node will leave
	err = crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), exterlIPPool.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Delete exterlIPPool error:%v", err)
	}
	time.Sleep(testDefaultInterval)

	assert.Equal(t, 4, s.memberNum(), "expected node member num is 4")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 0")
}

func TestCluster_Run(t *testing.T) {
	// init cluster with a exterlIPPool with node selector
	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentClusterPort + 1
	nodeName := "test_memberlist_node"
	nodeConfig := &config.NodeConfig{
		Name: nodeName,
		NodeIPAddr: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()

	exterlIPPool := crdv1a2.ExternalIPPool{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake_ip_pool",
		},
		Spec: crdv1a2.ExternalIPPoolSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}},
		},
	}
	crdClient := fakeversioned.NewSimpleClientset([]runtime.Object{&exterlIPPool}...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

	node0 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test_node0",
			Labels: map[string]string{"env": "pro"},
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.11"}}}}

	s, err := NewCluster(port, nodeInformer, nodeConfig, ipPoolInformer)
	if err != nil {
		t.Fatalf("New memberlist server error: %v", err)
	}

	// Make sure informers are running.
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	cache.WaitForCacheSync(stopCh, nodeInformer.Informer().HasSynced)
	cache.WaitForCacheSync(stopCh, ipPoolInformer.Informer().HasSynced)

	s.AddClusterNodeEventHandler(func(nodeName string, added bool) {
		t.Logf("notified node %s added (%t) node event handler", nodeName, added)
	})

	go s.Run(stopCh)

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node0, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// update node and selector deep equal
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node0, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// update node and oldMatch == newMatch
	node0.Labels = map[string]string{"env1": "test", "env": "pro"}
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node0, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// update node and oldMatch != newMatch; newMatch false and oldMatch true
	node0.Labels = map[string]string{"env": "test"}
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node0, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)
	assert.Equal(t, 1, s.memberNum(), "expected node member num is 1")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// update node and oldMatch != newMatch; newMatch true and oldMatch false
	node0.Labels = map[string]string{"env": "pro"}
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node0, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")

	// delete node
	err = clientset.CoreV1().Nodes().Delete(context.TODO(), node0.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 1, s.memberNum(), "expected node member num is 1")
	assert.Equal(t, 1, s.mList.NumMembers(), "expected alive node num is 1")
}

func TestCluster_ShouldSelectNodeFailedOrAddedBySortHash(t *testing.T) {
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
		name  string
		nodes []string
	}{
		{
			fmt.Sprintf("assign owner node for %d egress", egressNum),
			nodes[:10],
		},
		{
			// failover, when node failed, egress should move to available node
			"a node fail then egress should move",
			nodes[1:10],
		},
		{
			// egress should move when node added in cluster? how to move?
			"add new node then egress should move",
			nodes[:11],
		},
		{
			fmt.Sprintf("recover to %d nodes", 10),
			nodes[:10],
		},
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			nodes := testC.nodes
			nodeEgress := make(map[string][]string, len(nodes))
			hitCount := 0
			seqSum := 0
			for i := 0; i < egressNum; i++ {
				egressName := fmt.Sprintf("%d", i)
				for j := range nodes {
					myNode := nodes[j]
					if hitNode(nodes, egressName, myNode) {
						nodeEgress[myNode] = append(nodeEgress[myNode], egressName)
						hitCount++
						seqSum += i
					}
				}
			}
			assert.Equal(t, expectEgressSeqSum, seqSum, "egress seq")
			for _, node := range nodes {
				t.Logf("Node (%s) egress: %#v", node, nodeEgress[node])
			}
			assert.Equal(t, egressNum, hitCount, "hitNode egress total num should be 30")

		})
	}
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
		name    string
		nodes   []string
		conHash *consistenthash.Map
	}{
		{
			fmt.Sprintf("assign owner node for %d egress", egressNum),
			nodes[:10],
			consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			// failover, when node failed, egress should move to available node
			"a node fail then egress should move",
			nodes[1:10],
			consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			// egress should move when node added in cluster? how to move?
			"add new node then egress should move",
			nodes[:11],
			consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
		{
			fmt.Sprintf("recover to %d nodes", 10),
			nodes[:10],
			consistenthash.New(defaultVirtualNodeReplicas, nil),
		},
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			nodes := testC.nodes
			testC.conHash.Add(nodes...)
			nodeEgress := make(map[string][]string, len(nodes))
			hitCount := 0
			seqSum := 0
			for i := 0; i < egressNum; i++ {
				egressName := fmt.Sprintf("%d", i)
				for j := range nodes {
					myNode := nodes[j]
					if hitNodeByConsistentHash(testC.conHash, egressName, myNode) {
						nodeEgress[myNode] = append(nodeEgress[myNode], egressName)
						hitCount++
						seqSum += i
					}
				}
			}
			assert.Equal(t, expectEgressSeqSum, seqSum, "egress seq")
			for _, node := range nodes {
				t.Logf("Node (%s) egress: %#v", node, nodeEgress[node])
			}
			assert.Equal(t, egressNum, hitCount, "hitNode egress total num should be 30")
		})
	}
}

// replicas = 1
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-3-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 1
//cluster_test.go:612: Node: node2, egressNum: 1
//cluster_test.go:612: Node: node3, egressNum: 1
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 4
//cluster_test.go:612: Node: node2, egressNum: 2
//cluster_test.go:612: Node: node3, egressNum: 4
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-100-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 44
//cluster_test.go:612: Node: node2, egressNum: 43
//cluster_test.go:612: Node: node3, egressNum: 13
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-1000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 474
//cluster_test.go:612: Node: node2, egressNum: 408
//cluster_test.go:612: Node: node3, egressNum: 118
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 5284
//cluster_test.go:612: Node: node2, egressNum: 3390
//cluster_test.go:612: Node: node3, egressNum: 1326
//--- PASS: TestCluster_ShouldSelectByConstentHash (0.09s)

// replicas = 3
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-3-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 0
//cluster_test.go:612: Node: node2, egressNum: 2
//cluster_test.go:612: Node: node3, egressNum: 1
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 1
//cluster_test.go:612: Node: node2, egressNum: 5
//cluster_test.go:612: Node: node3, egressNum: 4
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-100-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 30
//cluster_test.go:612: Node: node2, egressNum: 33
//cluster_test.go:612: Node: node3, egressNum: 37
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-1000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 348
//cluster_test.go:612: Node: node2, egressNum: 317
//cluster_test.go:612: Node: node3, egressNum: 335
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 3318
//cluster_test.go:612: Node: node2, egressNum: 3469
//cluster_test.go:612: Node: node3, egressNum: 3213
//--- PASS: TestCluster_ShouldSelectByConstentHash (0.10s)

// replicas = 50
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-3-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 1
//cluster_test.go:612: Node: node2, egressNum: 2
//cluster_test.go:612: Node: node3, egressNum: 0
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 1
//cluster_test.go:612: Node: node2, egressNum: 4
//cluster_test.go:612: Node: node3, egressNum: 5
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-100-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 30
//cluster_test.go:612: Node: node2, egressNum: 32
//cluster_test.go:612: Node: node3, egressNum: 38
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-1000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 345
//cluster_test.go:612: Node: node2, egressNum: 297
//cluster_test.go:612: Node: node3, egressNum: 358
//=== RUN   TestCluster_ShouldSelectByConstentHash/select_node_from_alive_nodes-10000-egresses
//=== CONT  TestCluster_ShouldSelectByConstentHash
//cluster_test.go:612: Node: node1, egressNum: 3437
//cluster_test.go:612: Node: node2, egressNum: 2930
//cluster_test.go:612: Node: node3, egressNum: 3633
//--- PASS: TestCluster_ShouldSelectByConstentHash (0.10s)
//https://github.com/golang/groupcache/issues/29
func TestCluster_ShouldSelectByConstentHash(t *testing.T) {
	nodes := []string{"node1", "node2", "node3"}
	conHash := consistenthash.New(defaultVirtualNodeReplicas, nil)

	conHash.Add(nodes...)

	checkNum := func(count int, myNode string) int {
		totalNum := 0
		for i := 0; i < count; i++ {
			egressName := fmt.Sprintf("egress-%d", i)
			//egressName := fmt.Sprintf("%s-%d", genRandomStr(10), i)
			if hitNodeByConsistentHash(conHash, egressName, myNode) {
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
			name:      "select node from alive nodes",
			egressNum: 3,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 10,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 100,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 1000,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 10000,
		},
	}
	for _, tCase := range testCases {
		t.Run(fmt.Sprintf("%s-%d-egresses", tCase.name, tCase.egressNum), func(t *testing.T) {
			assert.Equal(t, tCase.egressNum, checkSum(tCase.egressNum))
		})
	}
}

//BenchmarkCluster_ShouldSelect
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes-16         	    4860	    244613 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes-16          	   52707	     22412 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes-16           	  538476	      2273 ns/op
//PASS
//BenchmarkCluster_ShouldSelectHitNodeByConsistentHash
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes-16         	12263878	        95.5 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes-16          	13036746	       103 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes-16           	14923483	        77.5 ns/op
//PASS
func BenchmarkCluster_ShouldSelect(b *testing.B) {
	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}

	benchmarkCases := []struct {
		name       string
		nodes      []string
		egressName string
		myNode     string
	}{
		{
			name:       "select node from 10000 alive nodes",
			nodes:      genNodes(10000),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 1000 alive nodes",
			nodes:      genNodes(1024),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 100 alive nodes",
			nodes:      genNodes(128),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 10 alive nodes",
			nodes:      genNodes(8),
			egressName: "egress-10",
			myNode:     "node-10",
		},
	}

	for i := range benchmarkCases {
		bc := benchmarkCases[i]
		b.Run(fmt.Sprintf("%s-hitNodeByConsistentHash", bc.name), func(b *testing.B) {
			b.ResetTimer()
			conHash := consistenthash.New(defaultVirtualNodeReplicas, nil)
			conHash.Add(bc.nodes...)
			for i := 0; i < b.N; i++ {
				hitNodeByConsistentHash(conHash, bc.egressName, bc.myNode)
			}
		})
		b.Run(fmt.Sprintf("%s-hitNodeBySortHash", bc.name), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hitNode(bc.nodes, bc.egressName, bc.myNode)
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
			mList: &memberlist.Memberlist{},
			NodeConfig: &config.NodeConfig{
				Name: nodeNme,
			},
			nodeName: nodeNme,
			conHash:  consistenthash.New(defaultVirtualNodeReplicas, nil),
		}
		return cluster
	}

	node1Cluster := genLocalNodeCluster("node1")
	node1Cluster.conHash.Add(nodes...)

	egressNum := 3
	hitCount := 0
	for i := 0; i < egressNum; i++ {
		egressName := fmt.Sprintf("%s-%d", genRandomStr(10), i)
		if node1Cluster.ShouldSelect(egressName) {
			hitCount++
		}
	}
	assert.Equal(t, egressNum, hitCount, "hitNode egress total num should be equal")
}
