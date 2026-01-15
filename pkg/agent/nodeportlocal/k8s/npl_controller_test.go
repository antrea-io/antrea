//go:build !windows
// +build !windows

// Copyright 2019 Antrea Authors
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

package k8s

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"
	npltesting "antrea.io/antrea/pkg/agent/nodeportlocal/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
)

const (
	defaultPodName        = "test-pod"
	defaultSvcName        = "test-svc"
	defaultNS             = "default"
	defaultPodKey         = defaultNS + "/" + defaultPodName
	defaultNodeName       = "test-node"
	defaultHostIP         = "10.10.10.10"
	defaultPodIP          = "192.168.32.10"
	defaultPort           = 80
	defaultAppSelectorKey = "foo"
	defaultAppSelectorVal = "test-pod"
	protocolTCP           = "tcp"
	protocolUDP           = "udp"
	defaultStartPort      = 61000
	defaultEndPort        = 65000
)

func newPortTable(mockIPTables rules.PodPortRules, mockPortOpener portcache.LocalPortOpener, isIPv6 bool) *portcache.PortTable {
	return &portcache.PortTable{
		PortTableCache: cache.NewIndexer(portcache.GetPortTableKey, cache.Indexers{
			portcache.NodePortIndex:    portcache.NodePortIndexFunc,
			portcache.PodEndpointIndex: portcache.PodEndpointIndexFunc,
			portcache.PodKeyIndex:      portcache.PodKeyIndexFunc,
		}),
		StartPort:       defaultStartPort,
		EndPort:         defaultEndPort,
		PortSearchStart: defaultStartPort,
		PodPortRules:    mockIPTables,
		LocalPortOpener: mockPortOpener,
		IsIPv6:          isIPv6,
	}
}

type fakeSocket struct{}

func (m *fakeSocket) Close() error {
	return nil
}

func newExpectedNPLAnnotations() *npltesting.ExpectedNPLAnnotations {
	return npltesting.NewExpectedNPLAnnotations(defaultStartPort, defaultEndPort)
}

func getTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultPodName,
			Namespace: defaultNS,
			Labels:    map[string]string{defaultAppSelectorKey: defaultAppSelectorVal},
		},
		Spec: corev1.PodSpec{
			NodeName: defaultNodeName,
			Containers: []corev1.Container{
				{
					Ports: []corev1.ContainerPort{},
				},
			},
		},
		Status: corev1.PodStatus{
			HostIP: defaultHostIP,
			PodIPs: []corev1.PodIP{
				{IP: defaultPodIP},
			},
		},
	}
}

func getTestSvc(targetPorts ...int32) *corev1.Service {
	var ports []corev1.ServicePort
	if len(targetPorts) == 0 {
		port := corev1.ServicePort{
			Port:     80,
			Protocol: corev1.ProtocolTCP,
			TargetPort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: defaultPort,
			},
		}
		ports = append(ports, port)
	} else {
		for i := range targetPorts {
			port := corev1.ServicePort{
				Port:     80,
				Protocol: corev1.ProtocolTCP,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: targetPorts[i],
				},
			}
			ports = append(ports, port)
		}
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaultSvcName,
			Namespace:   defaultNS,
			Annotations: map[string]string{types.NPLEnabledAnnotationKey: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:       corev1.ServiceTypeClusterIP,
			Selector:   map[string]string{defaultAppSelectorKey: defaultAppSelectorVal},
			Ports:      ports,
			IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
		},
	}
}

func getTestSvcWithPortName(portName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaultSvcName,
			Namespace:   defaultNS,
			Annotations: map[string]string{types.NPLEnabledAnnotationKey: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{defaultAppSelectorKey: defaultAppSelectorVal},
			Ports: []corev1.ServicePort{{
				Port:     80,
				Protocol: corev1.ProtocolTCP,
				TargetPort: intstr.IntOrString{
					Type:   intstr.String,
					StrVal: portName,
				},
			}},
			IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
		},
	}
}

type testData struct {
	*testing.T
	stopCh        chan struct{}
	ctrl          *gomock.Controller
	k8sClient     *k8sfake.Clientset
	portTable     *portcache.PortTable
	portTableIPv6 *portcache.PortTable
	svcInformer   cache.SharedIndexInformer
	nplController *NPLController
	wg            sync.WaitGroup
}

func (t *testData) runWrapper() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.nplController.Run(t.stopCh)
	}()
}

type customizePortOpenerExpectations func(*portcachetesting.MockLocalPortOpener)
type customizePodPortRulesExpectations func(*rulestesting.MockPodPortRules)

type testConfig struct {
	ipv4Enabled                    bool
	ipv6Enabled                    bool
	customPortOpenerExpectations   customizePortOpenerExpectations
	customPodPortRulesExpectations customizePodPortRulesExpectations
}

func newTestConfig() *testConfig {
	return &testConfig{
		ipv4Enabled: true,
	}
}

func (tc *testConfig) withCustomPortOpenerExpectations(fn customizePortOpenerExpectations) *testConfig {
	tc.customPortOpenerExpectations = fn
	return tc
}

func (tc *testConfig) withCustomPodPortRulesExpectations(fn customizePodPortRulesExpectations) *testConfig {
	tc.customPodPortRulesExpectations = fn
	return tc
}

func (tc *testConfig) withIPFamilies(ipv4Enabled, ipv6Enabled bool) *testConfig {
	tc.ipv4Enabled = ipv4Enabled
	tc.ipv6Enabled = ipv6Enabled
	return tc
}

// setUp can only be called from within a synctest bubble - it calls synctest.Wait
func setUp(t *testing.T, tc *testConfig, objects ...runtime.Object) *testData {
	t.Setenv("NODE_NAME", defaultNodeName)

	mockCtrl := gomock.NewController(t)

	mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)

	if tc.customPodPortRulesExpectations != nil {
		tc.customPodPortRulesExpectations(mockIPTables)
	} else {
		mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(nodePort int, podIP string, podPort int, protocol string) error {
				if nodePort == 0 || podIP == "" || podPort == 0 || protocol == "" {
					return fmt.Errorf("invalid argument to AddRule")
				}
				return nil
			},
		)
		mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		mockIPTables.EXPECT().AddAllRules(gomock.Any()).AnyTimes().DoAndReturn(
			func(nplList []rules.PodNodePort) error {
				for _, nplData := range nplList {
					if nplData.NodePort == 0 || nplData.PodIP == "" || nplData.PodPort == 0 || nplData.Protocol == "" {
						return fmt.Errorf("invalid entry in nplList argument to AddAllRules: %+v", nplData)
					}
				}
				return nil
			},
		)
	}

	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	if tc.customPortOpenerExpectations != nil {
		tc.customPortOpenerExpectations(mockPortOpener)
	} else {
		mockPortOpener.EXPECT().OpenLocalPort(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(&fakeSocket{}, nil)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultNodeName,
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: defaultHostIP},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "fd12:3456:789a:1::1"},
				{Type: corev1.NodeInternalIP, Address: "fd12:3456:789a:1::2"},
			},
		},
	}
	objects = append(objects, node)
	k8sClient := k8sfake.NewSimpleClientset(objects...)

	var portTableIPv4, portTableIPv6 *portcache.PortTable
	// For convenience, we use the same mocks in dual-stack mode.
	if tc.ipv4Enabled {
		portTableIPv4 = newPortTable(mockIPTables, mockPortOpener, false)
	}
	if tc.ipv6Enabled {
		portTableIPv6 = newPortTable(mockIPTables, mockPortOpener, true)
	}

	resyncPeriod := 0 * time.Minute
	// informerFactory is initialized and started from cmd/antrea-agent/agent.go
	informerFactory := informers.NewSharedInformerFactory(k8sClient, resyncPeriod)
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", defaultNodeName).String()
	}
	localPodInformer := coreinformers.NewFilteredPodInformer(
		k8sClient,
		metav1.NamespaceAll,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
		listOptions,
	)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()

	c := NewNPLController(k8sClient, localPodInformer, svcInformer, nodeInformer, portTableIPv4, portTableIPv6, defaultNodeName)

	data := &testData{
		T:             t,
		stopCh:        make(chan struct{}),
		ctrl:          mockCtrl,
		k8sClient:     k8sClient,
		portTable:     portTableIPv4,
		portTableIPv6: portTableIPv6,
		svcInformer:   svcInformer,
		nplController: c,
	}

	informerFactory.Start(data.stopCh)
	go localPodInformer.Run(data.stopCh)

	// Wait for NodeIPs to be "ready" (i.e., detected by the controller) before calling the
	// Run() method. Otherwise we may have a "race", with PollUntilContextCancel failing the
	// first condition function call, requiring a Sleep to advance time.
	synctest.Wait()
	require.True(t, c.nodeIPsReady())

	data.runWrapper()

	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	informerFactory.WaitForCacheSync(data.stopCh)
	cache.WaitForNamedCacheSync("AntreaAgentNPLController", data.stopCh, localPodInformer.HasSynced)

	t.Cleanup(data.tearDown)

	return data
}

func setUpWithTestServiceAndPod(t *testing.T, tc *testConfig, customNodePort *int) (*testData, *corev1.Service, *corev1.Pod) {
	testSvc := getTestSvc()
	testPod := getTestPod()

	testData := setUp(t, tc, testSvc, testPod)

	nodePort := defaultStartPort
	if customNodePort != nil {
		nodePort = *customNodePort
	}
	synctest.Wait()

	expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, &nodePort, defaultPort, protocolTCP)
	testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
	assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

	return testData, testSvc, testPod
}

func (t *testData) tearDown() {
	close(t.stopCh)
	t.wg.Wait()
}

func (t *testData) getNPLAnnotations(podName string) []types.NPLAnnotation {
	t.Helper()
	updatedPod, err := t.k8sClient.CoreV1().Pods(defaultNS).Get(t.Context(), podName, metav1.GetOptions{})
	require.NoError(t, err, "Failed to get Pod")
	annotation := updatedPod.GetAnnotations()
	data, ok := annotation[types.NPLAnnotationKey]
	if !ok {
		return nil
	}
	var nplValue []types.NPLAnnotation
	require.NoError(t, json.Unmarshal([]byte(data), &nplValue), "Invalid NPL annotation")
	return nplValue
}

func (t *testData) assertNoNPLAnnotation(podName string) {
	t.Helper()
	assert.Nil(t, t.getNPLAnnotations(podName))
}

func (t *testData) assertSingleNPLAnnotation(podName string) {
	t.Helper()
	assert.Len(t, t.getNPLAnnotations(podName), 1)
}

func (t *testData) assertExpectedNPLAnnotations(podName string, expectedAnnotations *npltesting.ExpectedNPLAnnotations) {
	t.Helper()
	expectedAnnotations.Check(t.T, t.getNPLAnnotations(podName))
}

func (t *testData) updateServiceOrFail(testSvc *corev1.Service) {
	_, err := t.k8sClient.CoreV1().Services(defaultNS).Update(t.Context(), testSvc, metav1.UpdateOptions{})
	require.NoError(t, err, "Service update failed")
	t.Logf("Successfully updated Service: %s", testSvc.Name)
}

func (t *testData) updatePodOrFail(testPod *corev1.Pod) {
	_, err := t.k8sClient.CoreV1().Pods(defaultNS).Update(t.Context(), testPod, metav1.UpdateOptions{})
	require.NoError(t, err, "Pod update failed")
	t.Logf("Successfully updated Pod: %s", testPod.Name)
}

// TestSvcNamespaceUpdate creates two Services in different Namespaces default and blue.
// It verifies the NPL annotation in the Pod in the default Namespace. It then deletes the
// Service in default Namespace, and verifies that the NPL annotation is also removed.
func TestSvcNamespaceUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvcDefaultNS := getTestSvc()
		testPodDefaultNS := getTestPod()
		testSvcBlue := getTestSvc()
		testSvcBlue.Namespace = "blue"
		testData := setUp(t, newTestConfig(), testSvcDefaultNS, testPodDefaultNS, testSvcBlue)

		// Remove Service testSvcDefaultNS.
		err := testData.k8sClient.CoreV1().Services(defaultNS).Delete(t.Context(), testSvcDefaultNS.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Service deletion failed")
		t.Logf("successfully deleted Service: %s", testSvcDefaultNS.Name)

		synctest.Wait()

		// Check that annotation and the rule are removed.
		testData.assertNoNPLAnnotation(testPodDefaultNS.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestSvcTypeUpdate updates Service type from ClusterIP to NodePort
// and checks whether Pod annotations are removed.
func TestSvcTypeUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		// Update Service type to NodePort.
		testSvc.Spec.Type = corev1.ServiceTypeNodePort
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		// Check that annotation and the rule are removed.
		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

		// Update Service type to ClusterIP.
		testSvc.Spec.Type = corev1.ServiceTypeClusterIP
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestSvcUpdateAnnotation updates the Service spec to disabled NPL. It then verifies that the Pod's
// NPL annotation is removed and that the port table is updated.
func TestSvcUpdateAnnotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		// Disable NPL.
		testSvc.Annotations = map[string]string{types.NPLEnabledAnnotationKey: "false"}
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		// Check that annotation and the rule is removed.
		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

		// Enable NPL back.
		testSvc.Annotations = map[string]string{types.NPLEnabledAnnotationKey: "true"}
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestSvcRemoveAnnotation is the same as TestSvcUpdateAnnotation, but it deletes the NPL enabled
// annotation, instead of setting its value to false.
func TestSvcRemoveAnnotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		testSvc.Annotations = nil
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestSvcUpdateSelector updates the Service selector so that it no longer selects the Pod, and
// verifies that the Pod annotation is removed.
func TestSvcUpdateSelector(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		testSvc.Spec.Selector = map[string]string{defaultAppSelectorKey: "invalid-selector"}
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

		testSvc.Spec.Selector = map[string]string{defaultAppSelectorKey: defaultAppSelectorVal}
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodUpdateSelectorLabel updates the Pod's labels so that the Pod is no longer selected by the
// Service. It then verifies that the Pod's NPL annotation is removed and that the port table is
// updated.
func TestPodUpdateSelectorLabel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, _, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		testPod.Labels = map[string]string{"invalid-label-key": defaultAppSelectorVal}
		testData.updatePodOrFail(testPod)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestSvcDelete deletes the Service. It then verifies that the Pod's NPL annotation is removed and
// that the port table is updated.
func TestSvcDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		err := testData.k8sClient.CoreV1().Services(defaultNS).Delete(t.Context(), testSvc.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Service deletion failed")
		t.Logf("successfully deleted Service: %s", testSvc.Name)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodDelete verifies that when a Pod gets deleted, the corresponding entry gets deleted from
// local port table as well.
func TestPodDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testData, _, testPod := setUpWithTestServiceAndPod(t, newTestConfig(), nil)

		err := testData.k8sClient.CoreV1().Pods(defaultNS).Delete(t.Context(), testPod.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Pod deletion failed")
		t.Logf("Successfully deleted Pod: %s", testPod.Name)

		synctest.Wait()

		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodAddMultiPort creates a Pod and a Service with two target ports.
// It verifies that the Pod's NPL annotation and the local port table are updated with both ports.
// It then updates the Service to remove one of the target ports.
func TestAddMultiPortPodSvc(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const newPort = 90
		testSvc := getTestSvc(defaultPort, newPort)
		testPod := getTestPod()
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP).Add(types.IPFamilyIPv4, nil, nil, newPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, newPort, protocolTCP))

		// Remove the second target port.
		testSvc.Spec.Ports = testSvc.Spec.Ports[:1]
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		// Wait for annotation to be updated (single mapping).
		expectedAnnotations = newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, newPort, protocolTCP))
	})
}

// TestPodAddMultiPort creates a Pod with multiple ports and a Service with only one target port.
// It verifies that the Pod's NPL annotation and the local port table are updated correctly,
// with only one port corresponding to the Service's single target port.
func TestAddMultiPortPodSinglePortSvc(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		newPort1 := defaultPort
		newPort2 := 81
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(newPort1)},
		)
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(newPort2)},
		)
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, newPort2, protocolTCP))
	})
}

// TestPodAddHostPort creates a Pod with host ports and verifies that the Pod's NPL annotation
// is updated with host port, without allocating extra port from NPL pool.
// No rule is required for this case.
func TestPodAddHostPort(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		hostPort := 4001
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolTCP},
		)
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, &hostPort, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodAddHostPort creates a Pod with multiple host ports having same value but different protocol.
// It verifies that the Pod's NPL annotation is updated with host port, without allocating extra port
// from NPL pool. No NPL rule is required for this case.
func TestPodAddHostPortMultiProtocol(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		hostPort := 4001
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolTCP},
		)
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolUDP},
		)
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, &hostPort, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodAddHostPortWrongProtocol creates a Pod with a host port but with protocol UDP instead of TCP.
// In this case, instead of using host port, a new port should be allocated from NPL port pool.
func TestPodAddHostPortWrongProtocol(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		hostPort := 4001
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolUDP},
		)
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestTargetPortWithName creates a Service with target port name in string.
// A Pod with matching container port name is also created and it is verified that
// the port table is updated with desired NPL rule.
func TestTargetPortWithName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		portName := "abcPort"
		testSvc := getTestSvcWithPortName(portName)
		testPod := getTestPod()
		testPod.Spec.Containers[0].Ports = append(
			testPod.Spec.Containers[0].Ports,
			corev1.ContainerPort{ContainerPort: int32(defaultPort), Name: portName, Protocol: corev1.ProtocolTCP},
		)
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

		testSvc = getTestSvcWithPortName("wrongPort")
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestMultiplePods creates multiple Pods and verifies that NPL annotations for both Pods are
// updated correctly, along with the local port table.
func TestMultiplePods(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod1 := getTestPod()
		testPod1.Name = "pod1"
		testPod1Key := testPod1.Namespace + "/" + testPod1.Name
		testPod1.Status.PodIPs = []corev1.PodIP{{IP: "192.168.32.1"}}
		testPod2 := getTestPod()
		testPod2.Name = "pod2"
		testPod2.Status.PodIPs = []corev1.PodIP{{IP: "192.168.32.2"}}
		testPod2Key := testPod2.Namespace + "/" + testPod2.Name
		testData := setUp(t, newTestConfig(), testSvc, testPod1, testPod2)

		synctest.Wait()

		pod1Value := testData.getNPLAnnotations(testPod1.Name)
		expectedAnnotationsPod1 := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotationsPod1.Check(t, pod1Value)
		assert.True(t, testData.portTable.RuleExists(testPod1Key, defaultPort, protocolTCP))

		pod2Value := testData.getNPLAnnotations(testPod2.Name)
		expectedAnnotationsPod2 := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotationsPod2.Check(t, pod2Value)
		assert.NotEqual(t, pod1Value[0].NodePort, pod2Value[0].NodePort)
		assert.True(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolTCP))
	})
}

// TestPodIPRecycle creates two Pods that have the same IP to simulate Pod IP recycle case.
// It verifies that NPL annotations and rules for a Pod is not affected by another Pod's lifecycle events.
func TestPodIPRecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		testSvc := getTestSvc()
		// pod1 and pod2 have the same IP, pod1 will run into terminated phase eventually.
		testPod1 := getTestPod()
		testPod1.Name = "pod1"
		testPod1Key := testPod1.Namespace + "/" + testPod1.Name
		testPod2 := getTestPod()
		testPod2.Name = "pod2"
		testPod2Key := testPod2.Namespace + "/" + testPod2.Name
		testData := setUp(t, newTestConfig(), testSvc, testPod1, testPod2)

		synctest.Wait()

		pod1Value := testData.getNPLAnnotations(testPod1.Name)
		expectedAnnotationsPod1 := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotationsPod1.Check(t, pod1Value)
		assert.True(t, testData.portTable.RuleExists(testPod1Key, defaultPort, protocolTCP))

		pod2Value := testData.getNPLAnnotations(testPod2.Name)
		expectedAnnotationsPod2 := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotationsPod2.Check(t, pod2Value)
		assert.NotEqual(t, pod1Value[0].NodePort, pod2Value[0].NodePort)
		assert.True(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolTCP))

		// After pod1 runs into succeeded phase, its NPL rule and annotation should be removed, while pod2 shouldn't be affected.
		updatedTestPod1 := testPod1.DeepCopy()
		updatedTestPod1.Status.Phase = corev1.PodSucceeded
		_, err := testData.k8sClient.CoreV1().Pods(updatedTestPod1.Namespace).UpdateStatus(ctx, updatedTestPod1, metav1.UpdateOptions{})
		require.NoError(t, err)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod1.Name)
		assert.False(t, testData.portTable.RuleExists(testPod1Key, defaultPort, protocolTCP))
		assert.True(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolTCP))

		// Deleting pod1 shouldn't delete pod2's NPL rule and annotation.
		require.NoError(t, testData.k8sClient.CoreV1().Pods(testPod1.Namespace).Delete(ctx, testPod1.Name, metav1.DeleteOptions{}))

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod2.Name)
		expectedAnnotationsPod2 = newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotationsPod2.Check(t, pod2Value)
		assert.True(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolTCP))

		// Deleting pod2 should delete pod2's NPL rule.
		require.NoError(t, testData.k8sClient.CoreV1().Pods(testPod2.Namespace).Delete(ctx, testPod2.Name, metav1.DeleteOptions{}))

		synctest.Wait()

		assert.False(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolTCP))
	})
}

// TestMultipleProtocols creates multiple Pods with multiple protocols and verifies that
// NPL annotations and iptable rules for both Pods and Protocols are updated correctly.
// In particular we make sure that a given NodePort is never used by more than one Pod.
// One Pod could use multiple NodePorts for different protocols with the same Pod port.
func TestMultipleProtocols(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tcpUdpSvcLabel := map[string]string{"tcp": "true", "udp": "true"}
		udpSvcLabel := map[string]string{"tcp": "false", "udp": "true"}

		testPod1 := getTestPod()
		testPod1.Name = "pod1"
		testPod1.Status.PodIPs = []corev1.PodIP{{IP: "192.168.32.1"}}
		testPod1.Labels = tcpUdpSvcLabel

		testPod2 := getTestPod()
		testPod2.Name = "pod2"
		testPod2.Status.PodIPs = []corev1.PodIP{{IP: "192.168.32.2"}}
		testPod2.Labels = udpSvcLabel
		testPod2Key := testPod2.Namespace + "/" + testPod2.Name

		// Create TCP/80 testSvc1 for pod1.
		testSvc1 := getTestSvc()
		testSvc1.Name = "svc1"
		testSvc1.Spec.Selector = tcpUdpSvcLabel

		// Create UDP/81 testSvc2 for pod2.
		testSvc2 := getTestSvc()
		testSvc2.Name = "svc2"
		testSvc2.Spec.Selector = udpSvcLabel
		testSvc2.Spec.Ports[0].Port = 81
		testSvc2.Spec.Ports[0].Protocol = protocolUDP
		testData := setUp(t, newTestConfig(), testSvc1, testSvc2, testPod1, testPod2)

		synctest.Wait()

		pod1Value := testData.getNPLAnnotations(testPod1.Name)
		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		expectedAnnotations.Check(t, pod1Value)

		// Check the annotation for pod2: protocol should be UDP and the NodePort
		// assigned to pod2 should be different from the one assigned to pod1.
		pod2Value := testData.getNPLAnnotations(testPod2.Name)
		expectedAnnotationsPod2 := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolUDP)
		expectedAnnotationsPod2.Check(t, pod2Value)
		assert.NotEqual(t, pod1Value[0].NodePort, pod2Value[0].NodePort)
		assert.True(t, testData.portTable.RuleExists(testPod2Key, defaultPort, protocolUDP))

		// Update testSvc2 to serve TCP/80 and UDP/81 both, so pod2 is
		// exposed on both TCP and UDP, with different NodePorts.
		testSvc2.Spec.Ports = append(testSvc2.Spec.Ports, corev1.ServicePort{
			Port:     80,
			Protocol: corev1.ProtocolTCP,
			TargetPort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 80,
			},
		})
		testData.updateServiceOrFail(testSvc2)

		synctest.Wait()

		pod2ValueUpdate := testData.getNPLAnnotations(testPod2.Name)

		// The new NodePort should be the next available port number,
		// because the implementation allocates ports sequentially.
		var pod2nodeport int
		if pod1Value[0].NodePort > pod2Value[0].NodePort {
			pod2nodeport = pod1Value[0].NodePort + 1
		} else {
			pod2nodeport = pod2Value[0].NodePort + 1
		}
		expectedAnnotationsPod2.Add(types.IPFamilyIPv4, nil, &pod2nodeport, defaultPort, protocolTCP)
		expectedAnnotationsPod2.Check(t, pod2ValueUpdate)
	})
}

func TestMultipleServicesSameBackendPod(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc1 := getTestSvc()
		testPod := getTestPod()
		testSvc2 := getTestSvc(9090)
		testSvc2.Name = "svc2"
		testData := setUp(t, newTestConfig(), testSvc1, testSvc2, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP).Add(types.IPFamilyIPv4, nil, nil, 9090, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, 9090, protocolTCP))
	})
}

// TestInitInvalidAnnotation simulates the case where the agent reboots and for some reason an NPL
// annotation is invalid. The annotation should eventually be replaced by a valid one.
func TestInitInvalidAnnotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		testPod.Annotations = map[string]string{
			types.NPLAnnotationKey: "",
		}
		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			// No initial rule should be synced.
			mockIPTables.EXPECT().AddAllRules(gomock.Len(0)).Return(nil)
			mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		})
		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestInitNodePortOutOfRange simulates the case where the agent reboots and the NPL port range has
// changed. The existing NPL annotation should be replaced by one with a valid NodePort (i.e., with
// a value in the new range) and the correct rule should be installed.
func TestInitNodePortOutOfRange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		nplAnnotation := []types.NPLAnnotation{
			{
				PodPort:  defaultPort,
				NodeIP:   defaultHostIP,
				NodePort: 30000,
				Protocol: protocolTCP,
			},
		}
		nplAnnotationBytes, err := json.Marshal(nplAnnotation)
		require.NoError(t, err)
		testPod.Annotations = map[string]string{
			types.NPLAnnotationKey: string(nplAnnotationBytes),
		}
		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			// No initial rule should be synced.
			mockIPTables.EXPECT().AddAllRules(gomock.Len(0)).Return(nil)
			mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		})
		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestInitMissingPodIP simulates the case where the agent reboots and one Pod has an existing NPL
// annotation but is mising its Pod IP. We expect the annotation to be removed until the Pod IP
// becomes available, at which point a new NPL annotation should be added.
func TestInitMissingPodIP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		testPod.Status.PodIPs = nil
		nplAnnotation := []types.NPLAnnotation{
			{
				PodPort:  defaultPort,
				NodeIP:   defaultHostIP,
				NodePort: defaultStartPort,
				Protocol: protocolTCP,
			},
		}
		nplAnnotationBytes, err := json.Marshal(nplAnnotation)
		require.NoError(t, err)
		testPod.Annotations = map[string]string{
			types.NPLAnnotationKey: string(nplAnnotationBytes),
		}
		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			// No initial rule should be synced.
			mockIPTables.EXPECT().AddAllRules(gomock.Len(0)).Return(nil)
			mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		})
		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))

		testPod.Status.PodIPs = []corev1.PodIP{{IP: defaultPodIP}}
		testData.updatePodOrFail(testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestInitIncompleteRuleInAnnotation simulates the case where the agent reboots and one Pod has an
// existing NPL annotation with an incomplete rule (e.g., missing podPort). The annotation should
// eventually be replaced by a valid one.
func TestInitIncompleteRuleInAnnotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		nplAnnotation := []types.NPLAnnotation{
			{
				// Omit intentionally.
				// PodPort:  defaultPort,
				NodeIP:   defaultHostIP,
				NodePort: defaultStartPort,
				Protocol: protocolTCP,
			},
		}
		nplAnnotationBytes, err := json.Marshal(nplAnnotation)
		require.NoError(t, err)
		testPod.Annotations = map[string]string{
			types.NPLAnnotationKey: string(nplAnnotationBytes),
		}
		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			// No initial rule should be synced.
			mockIPTables.EXPECT().AddAllRules(gomock.Len(0)).Return(nil)
			mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		})
		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

var (
	errPortTaken = fmt.Errorf("port taken")
)

// TestNodePortAlreadyBoundTo validates that when a port with TCP protocol is already bound to,
// the next sequential TCP port should be selected for NPL when it is available.
func TestNodePortAlreadyBoundTo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodePort1 := defaultStartPort
		nodePort2 := nodePort1 + 1
		testConfig := newTestConfig().withCustomPortOpenerExpectations(func(mockPortOpener *portcachetesting.MockLocalPortOpener) {
			gomock.InOrder(
				// 1. port1 is checked for TCP availability -> error
				mockPortOpener.EXPECT().OpenLocalPort(nodePort1, protocolTCP, false).Return(nil, errPortTaken),
				// 2. port2 is checked for TCP availability -> success
				mockPortOpener.EXPECT().OpenLocalPort(nodePort2, protocolTCP, false).Return(&fakeSocket{}, nil),
			)
		})
		customNodePort := defaultStartPort + 1
		testData, _, testPod := setUpWithTestServiceAndPod(t, testConfig, &customNodePort)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, &nodePort2, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
	})
}

func TestSyncRulesError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			gomock.InOrder(
				mockIPTables.EXPECT().AddAllRules(gomock.Any()).Return(fmt.Errorf("iptables failure")),
				mockIPTables.EXPECT().AddAllRules(gomock.Any()).Return(nil).AnyTimes(),
			)
		})

		testSvc := getTestSvc()
		testPod := getTestPod()
		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
	})
}

func TestSingleRuleDeletionError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newPort := 90
		testSvc := getTestSvc(defaultPort, int32(newPort))
		testPod := getTestPod()

		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			mockIPTables.EXPECT().AddAllRules(gomock.Any()).AnyTimes()
			gomock.InOrder(
				mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2),
				mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("iptables failure")),
				mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			)
		})

		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP).Add(types.IPFamilyIPv4, nil, nil, newPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, newPort, protocolTCP))

		// Remove the second target port, to force one mapping to be deleted.
		testSvc.Spec.Ports = testSvc.Spec.Ports[:1]
		testData.updateServiceOrFail(testSvc)

		// The first sync will fail because of the iptables error.
		synctest.Wait()
		// Annotation should be unchanged.
		expectedAnnotations.Check(t, testData.getNPLAnnotations(testPod.Name))
		// Rule should have been marked as defunct.
		nplData := testData.portTable.GetEntry(defaultPodKey, newPort, protocolTCP)
		require.NotNil(t, nplData)
		assert.True(t, nplData.Defunct())
		// We have to wait for minRetryDelay for the controller to retry.
		time.Sleep(minRetryDelay)
		// This time, deletion should succeed.
		synctest.Wait()

		// Wait for annotation to be updated (single mapping).
		expectedAnnotations = newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, newPort, protocolTCP))
	})
}

func TestPreventDefunctRuleReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newPort := 90
		testSvc := getTestSvc(defaultPort, int32(newPort))
		testPod := getTestPod()

		testConfig := newTestConfig().withCustomPodPortRulesExpectations(func(mockIPTables *rulestesting.MockPodPortRules) {
			mockIPTables.EXPECT().AddAllRules(gomock.Any()).AnyTimes()
			gomock.InOrder(
				mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2),
				mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("iptables failure")),
				mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
				mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			)
		})

		testData := setUp(t, testConfig, testSvc, testPod)

		synctest.Wait()

		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, nil, nil, defaultPort, protocolTCP).Add(types.IPFamilyIPv4, nil, nil, newPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, newPort, protocolTCP))

		ports := testSvc.Spec.Ports
		// Remove the second target port, to force one mapping to be deleted.
		testSvc.Spec.Ports = testSvc.Spec.Ports[:1]
		testData.updateServiceOrFail(testSvc)

		synctest.Wait()

		// Make sure that the entry has been marked as defunct.
		nplData := testData.portTable.GetEntry(defaultPodKey, newPort, protocolTCP)
		require.NotNil(t, nplData)
		assert.True(t, nplData.Defunct())

		// We now restore the second target port that we previously deleted.
		// Because of the Service update, the Pod will be processed immediately (no need to
		// sleep for minRetryDelay).
		// The controller will need to delete the defunct rule first, before adding it back.
		// We know that behavior is correct if all gomock expectations have been satisfied
		// when the test exists (which is checked implicitly).
		testSvc.Spec.Ports = ports
		_, err := testData.k8sClient.CoreV1().Services(defaultNS).Update(t.Context(), testSvc, metav1.UpdateOptions{})
		require.NoError(t, err)

		synctest.Wait()
	})
}

// TestPodIPReset tests the case where a Pod "loses" its IP address. This can theoretically happen
// when there is an issue with the Pod Sandbox. For example, after a Node restart, a Pod's status
// may change to Unknown and its IP may be reset. After a while, the Sandbox is recreated, and the
// Pod goes back to Running with a new IP.
func TestPodIPReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		nplData := testData.portTable.GetEntry(defaultPodKey, defaultPort, protocolTCP)
		require.NotNil(t, nplData)
		require.Equal(t, defaultPodIP, nplData.PodIP)

		testPod.Status.PodIPs = nil
		testData.updatePodOrFail(testPod)

		synctest.Wait()

		testData.assertNoNPLAnnotation(testPod.Name)
		assert.False(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestPodIPChange tests the case where a Pod's IP address changes. This can happen when a Sandbox
// is recreated (see TestPodIPReset above). This can also happen when a Pod is deleted and recreated
// with the same name and a different IP: because the NPLController uses a workqueue, the DELETE and
// CREATE events can theoretically be merged and processed as a single UPDATE event.
func TestPodIPChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		testData.assertSingleNPLAnnotation(testPod.Name)
		nplData := testData.portTable.GetEntry(defaultPodKey, defaultPort, protocolTCP)
		require.NotNil(t, nplData)
		require.Equal(t, defaultPodIP, nplData.PodIP)

		newPodIP := "192.168.32.11"
		testPod.Status.PodIPs = []corev1.PodIP{{IP: newPodIP}}
		testData.updatePodOrFail(testPod)

		synctest.Wait()

		nplData = testData.portTable.GetEntry(defaultPodKey, defaultPort, protocolTCP)
		require.NotNil(t, nplData)
		assert.Equal(t, newPodIP, nplData.PodIP)
	})
}

// TestNodeIPUpdate tests that when Node IP addresses change, all local Pods are reconciled
// with the new Node IPs.
func TestNodeIPUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testPod := getTestPod()
		testData := setUp(t, newTestConfig(), testSvc, testPod)

		synctest.Wait()

		// Verify initial annotation with original Node IP
		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, ptr.To(defaultHostIP), nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)

		// Update Node external IP using UpdateStatus
		newNodeIP := "10.10.10.20"
		node, err := testData.k8sClient.CoreV1().Nodes().Get(t.Context(), defaultNodeName, metav1.GetOptions{})
		require.NoError(t, err)
		node.Status.Addresses = []corev1.NodeAddress{
			{Type: corev1.NodeExternalIP, Address: newNodeIP},
			{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
		}
		_, err = testData.k8sClient.CoreV1().Nodes().UpdateStatus(t.Context(), node, metav1.UpdateOptions{})
		require.NoError(t, err)

		synctest.Wait()

		// Verify annotation is updated with new Node IP
		expectedAnnotations = newExpectedNPLAnnotations().Add(types.IPFamilyIPv4, &newNodeIP, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestIPv6Only verifies that NPL works correctly with IPv6-only Pods and Services.
func TestIPv6Only(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testSvc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
		testPod := getTestPod()
		testPod.Status.PodIPs = []corev1.PodIP{{IP: "fd12:3456:789a:3::10"}}
		testData := setUp(t, newTestConfig().withIPFamilies(false, true), testSvc, testPod)

		synctest.Wait()

		ipv6NodeIP := "fd12:3456:789a:1::1"
		expectedAnnotations := newExpectedNPLAnnotations().Add(types.IPFamilyIPv6, &ipv6NodeIP, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTableIPv6.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}

// TestDualStack verifies that NPL works correctly with dual-stack Pods and Services.
// It should create separate NPL mappings for each IP family.
func TestDualStack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testSvc := getTestSvc()
		testSvc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
		testPod := getTestPod()
		testPod.Status.PodIPs = []corev1.PodIP{
			{IP: "192.168.32.10"},
			{IP: "fd12:3456:789a:3::10"},
		}
		testData := setUp(t, newTestConfig().withIPFamilies(true, true), testSvc, testPod)

		synctest.Wait()

		// Build expected annotations with both IPv4 and IPv6
		ipv4NodeIP := defaultHostIP
		ipv6NodeIP := "fd12:3456:789a:1::1"
		expectedAnnotations := newExpectedNPLAnnotations().
			Add(types.IPFamilyIPv4, &ipv4NodeIP, nil, defaultPort, protocolTCP).
			Add(types.IPFamilyIPv6, &ipv6NodeIP, nil, defaultPort, protocolTCP)
		testData.assertExpectedNPLAnnotations(testPod.Name, expectedAnnotations)
		assert.True(t, testData.portTable.RuleExists(defaultPodKey, defaultPort, protocolTCP))
		assert.True(t, testData.portTableIPv6.RuleExists(defaultPodKey, defaultPort, protocolTCP))
	})
}
