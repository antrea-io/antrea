package e2e

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

const (
	// TODO(gran): correct prefix
	IPPoolAnnotationKey string = "ipam.antrea.io/ippools"
)

var (
	subnetIPv4RangesMap = map[int]crdv1alpha2.IPPool{
		0: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-0",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: 4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.240.100",
					End:   "192.168.240.109",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.240.1",
						PrefixLength: 24,
						VLAN:         "",
					}}},
			},
		},
	}
)

func TestAntreaIPAM(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	ippool, err := createIPPool(t, data, 0)
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ippool.Name)
	mutateFunc := func(namespace *corev1.Namespace) {
		if namespace.Annotations == nil {
			namespace.Annotations = map[string]string{}
		}
		namespace.Annotations[IPPoolAnnotationKey] = ippool.Name
	}
	err = data.createNamespace(testAntreaIPAMNamespace, mutateFunc)
	if err != nil {
		t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
	}
	defer deleteAntreaIPAMNamespace(t, data)

	t.Run("testAntreaIPAMPodToAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivitySameNode", func(t *testing.T) {
		testAntreaIPAMPodConnectivitySameNode(t, data)
	})
	t.Run("testAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		t.Skipf("Not supported currently")
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testNamespace, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivityDifferentNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testAntreaIPAMPodConnectivityDifferentNodes(t, data)
	})
	t.Run("testAntreaIPAMPodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testNamespace)
	})
	t.Run("testAntreaIPAMOVSRestartSameNode", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		skipIfHasWindowsNodes(t)
		testOVSRestartSameNode(t, data, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivityAfterAntreaRestart", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testPodConnectivityAfterAntreaRestart(t, data, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMOVSFlowReplay", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testOVSFlowReplay(t, data, testAntreaIPAMNamespace)
	})
}

func testAntreaIPAMPodConnectivitySameNode(t *testing.T, data *TestData) {
	numPods := 2 // Two AntreaIPAM Pods, can be increased
	podInfos := make([]podInfo, numPods)
	for idx := range podInfos {
		podInfos[idx].name = randName(fmt.Sprintf("test-antrea-ipam-pod-%d-", idx))
		podInfos[idx].namespace = testAntreaIPAMNamespace
	}
	// One Per-Node IPAM Pod
	podInfos = append(podInfos, podInfo{
		name:      randName("test-pod-0-"),
		namespace: testNamespace,
	})
	// If there are Windows Nodes, set workerNode to one of them.
	workerNode := workerNodeName(1)
	if len(clusterInfo.windowsNodes) != 0 {
		workerNode = workerNodeName(clusterInfo.windowsNodes[0])
	}

	t.Logf("Creating %d agnhost Pods on '%s'", numPods+1, workerNode)
	for i := range podInfos {
		podInfos[i].os = clusterInfo.nodesOS[workerNode]
		if err := data.createAgnhostPodOnNodeWithAnnotations(podInfos[i].name, podInfos[i].namespace, workerNode, nil); err != nil {
			t.Fatalf("Error when creating agnhost test Pod '%s': %v", podInfos[i], err)
		}
		defer deletePodWrapper(t, data, podInfos[i].namespace, podInfos[i].name)
	}

	data.runPingMesh(t, podInfos, agnhostContainerName)
}

func testAntreaIPAMPodConnectivityDifferentNodes(t *testing.T, data *TestData) {
	maxNodes := 3
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, testNamespace, "differentnodes")
	defer deletePods()
	antreaIPAMPodInfos, deleteAntreaIPAMPods := createPodsOnDifferentNodes(t, data, testAntreaIPAMNamespace, "antreaipam-differentnodes")
	defer deleteAntreaIPAMPods()

	if len(podInfos) > maxNodes {
		podInfos = podInfos[:maxNodes]
		antreaIPAMPodInfos = antreaIPAMPodInfos[:maxNodes]
	}
	podInfos = append(podInfos, antreaIPAMPodInfos...)
	data.runPingMesh(t, podInfos, agnhostContainerName)
}

func deleteAntreaIPAMNamespace(tb testing.TB, data *TestData) {
	tb.Logf("Deleting '%s' K8s Namespace", testAntreaIPAMNamespace)
	if err := data.deleteNamespace(testAntreaIPAMNamespace, defaultTimeout); err != nil {
		tb.Logf("Error when tearing down test: %v", err)
	}
}

func createIPPool(tb testing.TB, data *TestData, vlan int) (*crdv1alpha2.IPPool, error) {
	ipv4IPPool := subnetIPv4RangesMap[vlan]
	tb.Logf("Creating IPPool '%s'", ipv4IPPool.Name)
	return data.crdClient.CrdV1alpha2().IPPools().Create(context.TODO(), &ipv4IPPool, metav1.CreateOptions{})
}

func deleteIPPoolWrapper(tb testing.TB, data *TestData, name string) {
	tb.Logf("Deleting IPPool '%s'", name)
	if err := data.crdClient.CrdV1alpha2().IPPools().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		tb.Logf("Error when deleting IPPool: %v", err)
	}
}
