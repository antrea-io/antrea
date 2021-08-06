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

package nodeportlocal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	nplk8s "antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"
)

func newPortTable(mockIPTables rules.PodPortRules, mockPortOpener portcache.LocalPortOpener) *portcache.PortTable {
	ptable := portcache.PortTable{StartPort: 61000, EndPort: 65000}
	ptable.Table = make(map[int]portcache.NodePortData)
	ptable.PodPortRules = mockIPTables
	ptable.LocalPortOpener = mockPortOpener
	return &ptable
}

const (
	defaultPodName        = "test-pod"
	defaultSvcName        = "test-svc"
	defaultNS             = "default"
	defaultNodeName       = "test-node"
	defaultHostIP         = "10.10.10.10"
	defaultPodIP          = "192.168.32.10"
	defaultPort           = 80
	defaultAppSelectorKey = "foo"
	defaultAppSelectorVal = "test-pod"
)

type fakeSocket struct{}

func (m *fakeSocket) Close() error {
	return nil
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
			PodIP:  defaultPodIP,
		},
	}
}

func getTestSvc(targetPorts ...int32) *corev1.Service {
	var ports []corev1.ServicePort
	if len(targetPorts) == 0 {
		port := corev1.ServicePort{
			Port:     80,
			Protocol: "TCP",
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
				Protocol: "TCP",
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
			Annotations: map[string]string{nplk8s.NPLEnabledAnnotationKey: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{defaultAppSelectorKey: defaultAppSelectorVal},
			Ports:    ports,
		},
	}
}

func getTestSvcWithPortName(portName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaultSvcName,
			Namespace:   defaultNS,
			Annotations: map[string]string{nplk8s.NPLEnabledAnnotationKey: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{defaultAppSelectorKey: defaultAppSelectorVal},
			Ports: []corev1.ServicePort{{
				Port:     80,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					Type:   intstr.String,
					StrVal: portName,
				},
			}},
		},
	}
}

type testData struct {
	*testing.T
	stopCh         chan struct{}
	ctrl           *gomock.Controller
	k8sClient      *k8sfake.Clientset
	portTable      *portcache.PortTable
	mockPortOpener *portcachetesting.MockLocalPortOpener
	wg             sync.WaitGroup
}

func (data *testData) runWrapper(c *nplk8s.NPLController) {
	data.wg.Add(1)
	go func() {
		defer data.wg.Done()
		c.Run(data.stopCh)
	}()
}

type testConfig struct {
	defaultPortOpenerExpectations bool
}

func newTestConfig() *testConfig {
	return &testConfig{
		defaultPortOpenerExpectations: true,
	}
}

func (tc *testConfig) withDefaultPortOpenerExpectations(v bool) *testConfig {
	tc.defaultPortOpenerExpectations = false
	return tc
}

func setUp(t *testing.T, tc *testConfig, objects ...runtime.Object) *testData {
	os.Setenv("NODE_NAME", defaultNodeName)

	mockCtrl := gomock.NewController(t)

	mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
	mockIPTables.EXPECT().AddRule(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockIPTables.EXPECT().DeleteRule(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockIPTables.EXPECT().AddAllRules(gomock.Any()).AnyTimes()

	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	if tc.defaultPortOpenerExpectations {
		mockPortOpener.EXPECT().OpenLocalPort(gomock.Any()).AnyTimes().Return(&fakeSocket{}, nil)
	}

	data := &testData{
		T:              t,
		stopCh:         make(chan struct{}),
		ctrl:           mockCtrl,
		k8sClient:      k8sfake.NewSimpleClientset(objects...),
		portTable:      newPortTable(mockIPTables, mockPortOpener),
		mockPortOpener: mockPortOpener,
	}

	// informerFactory is initialized and started from cmd/antrea-agent/agent.go
	informerFactory := informers.NewSharedInformerFactory(data.k8sClient, resyncPeriod)

	c, err := InitController(data.k8sClient, informerFactory, data.portTable, defaultNodeName)
	require.NoError(t, err)

	data.runWrapper(c)
	informerFactory.Start(data.stopCh)

	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	informerFactory.WaitForCacheSync(data.stopCh)

	return data
}

func setUpWithTestServiceAndPod(t *testing.T, tc *testConfig) (*testData, *corev1.Service, *corev1.Pod) {
	testSvc := getTestSvc()
	testPod := getTestPod()

	testData := setUp(t, tc, testSvc, testPod)

	defer func() {
		if t.Failed() {
			testData.tearDown()
		}
	}()

	// only use "require"s here: if something fails during setup, we ensure that we call
	// teardown and that the test will not proceed.
	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	testData.checkAnnotationValue(value, defaultPort)
	require.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))

	return testData, testSvc, testPod
}

func (t *testData) tearDown() {
	close(t.stopCh)
	t.wg.Wait()
	t.ctrl.Finish()
	os.Unsetenv("NODE_NAME")
}

func (t *testData) pollForPodAnnotation(podName string, found bool) (string, error) {
	var data string
	var exists bool
	// do not use PollImmediate: 1 second is reserved for the controller to do his job and
	// update Pod NPL annotations as needed.
	err := wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		updatedPod, err := t.k8sClient.CoreV1().Pods(defaultNS).Get(context.TODO(), podName, metav1.GetOptions{})
		require.NoError(t, err, "Failed to get Pod")
		ann := updatedPod.GetAnnotations()
		data, exists = ann[nplk8s.NPLAnnotationKey]
		if found {
			return exists, nil
		}
		return !exists, nil
	})

	return data, err
}

// checkAnnotationValue unmarshals the NPL annotations stored in the "value" string. It then
// verifies that the correct number of NPL entries is present and that they include the expected
// Node IP and Pod Port. It then returns the parsed annotations, in case the test needs to run some
// validation on the Node Port values.
func (t *testData) checkAnnotationValue(value string, podPort ...int) []nplk8s.NPLAnnotation {
	var nplValue []nplk8s.NPLAnnotation
	err := json.Unmarshal([]byte(value), &nplValue)
	require.NoError(t, err, "Error when unmarshalling NPL annotation")

	require.Equal(t, len(podPort), len(nplValue))
	for idx, port := range podPort {
		assert.Equal(t, defaultHostIP, nplValue[idx].NodeIP)
		assert.Equal(t, port, nplValue[idx].PodPort)
	}
	return nplValue
}

func (t *testData) updateServiceOrFail(testSvc *corev1.Service) {
	_, err := t.k8sClient.CoreV1().Services(defaultNS).Update(context.TODO(), testSvc, metav1.UpdateOptions{})
	require.NoError(t, err, "Service update failed")
	t.Logf("Successfully updated Service: %s", testSvc.Name)
}

func (t *testData) updatePodOrFail(testPod *corev1.Pod) {
	_, err := t.k8sClient.CoreV1().Pods(defaultNS).Update(context.TODO(), testPod, metav1.UpdateOptions{})
	require.NoError(t, err, "Pod update failed")
	t.Logf("Successfully updated Pod: %s", testPod.Name)
}

// TestSvcNamespaceUpdate creates two Services in different Namespaces default and blue.
// It verifies the NPL annotation in the Pod in the default Namespace. It then deletes the
// Service in default Namespace, and verifies that the NPL annotation is also removed.
func TestSvcNamespaceUpdate(t *testing.T) {
	testSvcDefaultNS := getTestSvc()
	testPodDefaultNS := getTestPod()
	testSvcBlue := getTestSvc()
	testSvcBlue.Namespace = "blue"
	testData := setUp(t, newTestConfig(), testSvcDefaultNS, testPodDefaultNS, testSvcBlue)
	defer testData.tearDown()

	// Remove Service testSvcDefaultNS.
	err := testData.k8sClient.CoreV1().Services(defaultNS).Delete(context.TODO(), testSvcDefaultNS.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Service deletion failed")
	t.Logf("successfully deleted Service: %s", testSvcDefaultNS.Name)

	// Check that annotation and the rule are removed.
	_, err = testData.pollForPodAnnotation(testPodDefaultNS.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcTypeUpdate updates Service type from ClusterIP to NodePort
// and checks whether Pod annotations are removed.
func TestSvcTypeUpdate(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	// Update Service type to NodePort.
	testSvc.Spec.Type = "NodePort"
	testData.updateServiceOrFail(testSvc)

	// Check that annotation and the rule are removed.
	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))

	// Update Service type to ClusterIP.
	testSvc.Spec.Type = "ClusterIP"
	testData.updateServiceOrFail(testSvc)

	_, err = testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcUpdateAnnotation updates the Service spec to disabled NPL. It then verifies that the Pod's
// NPL annotation is removed and that the port table is updated.
func TestSvcUpdateAnnotation(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	// Disable NPL.
	testSvc.Annotations = map[string]string{nplk8s.NPLEnabledAnnotationKey: "false"}
	testData.updateServiceOrFail(testSvc)

	// Check that annotation and the rule is removed.
	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))

	// Enable NPL back.
	testSvc.Annotations = map[string]string{nplk8s.NPLEnabledAnnotationKey: "true"}
	testData.updateServiceOrFail(testSvc)

	_, err = testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcRemoveAnnotation is the same as TestSvcUpdateAnnotation, but it deletes the NPL enabled
// annotation, instead of setting its value to false.
func TestSvcRemoveAnnotation(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	testSvc.Annotations = nil
	testData.updateServiceOrFail(testSvc)

	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcUpdateSelector updates the Service selector so that it no longer selects the Pod, and
// verifies that the Pod annotation is removed.
func TestSvcUpdateSelector(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	testSvc.Spec.Selector = map[string]string{defaultAppSelectorKey: "invalid-selector"}
	testData.updateServiceOrFail(testSvc)

	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))

	testSvc.Spec.Selector = map[string]string{defaultAppSelectorKey: defaultAppSelectorVal}
	testData.updateServiceOrFail(testSvc)

	_, err = testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodUpdateSelectorLabel updates the Pod's labels so that the Pod is no longer selected by the
// Service. It then verifies that the Pod's NPL annotation is removed and that the port table is
// updated.
func TestPodUpdateSelectorLabel(t *testing.T) {
	testData, _, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	testPod.Labels = map[string]string{"invalid-label-key": defaultAppSelectorVal}
	testData.updatePodOrFail(testPod)

	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcDelete deletes the Service. It then verifies that the Pod's NPL annotation is removed and
// that the port table is updated.
func TestSvcDelete(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	err := testData.k8sClient.CoreV1().Services(defaultNS).Delete(context.TODO(), testSvc.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Service deletion failed")
	t.Logf("successfully deleted Service: %s", testSvc.Name)

	_, err = testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodDelete verifies that when a Pod gets deleted, the corresponding entry gets deleted from
// local port table as well.
func TestPodDelete(t *testing.T) {
	testData, _, testPod := setUpWithTestServiceAndPod(t, newTestConfig())
	defer testData.tearDown()

	err := testData.k8sClient.CoreV1().Pods(defaultNS).Delete(context.TODO(), testPod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Pod deletion failed")
	t.Logf("Successfully deleted Pod: %s", testPod.Name)

	err = wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		return !testData.portTable.RuleExists(defaultPodIP, defaultPort), nil
	})
	assert.NoError(t, err, "Error when polling for port table update")
}

// TestPodAddMultiPort creates a Pod and a Service with two target ports.
// It verifies that the Pod's NPL annotation and the local port table are updated with both ports.
func TestAddMultiPortPodSvc(t *testing.T) {
	newPort := 90
	testSvc := getTestSvc(defaultPort, int32(newPort))
	testPod := getTestPod()
	testData := setUp(t, newTestConfig(), testSvc, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort, newPort)
	assert.NotEqual(t, nplData[0].NodePort, nplData[1].NodePort)
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, newPort))
}

// TestPodAddMultiPort creates a Pod with multiple ports and a Service with only one target port.
// It verifies that the Pod's NPL annotation and the local port table are updated correctly,
// with only one port corresponding to the Service's single target port.
func TestAddMultiPortPodSinglePortSvc(t *testing.T) {
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
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort)
	assert.Len(t, nplData, 1)
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, newPort2))
}

// TestPodAddHostPort creates a Pod with host ports and verifies that the Pod's NPL annotation
// is updated with host port, without allocating extra port from NPL pool.
// No rule is required for this case.
func TestPodAddHostPort(t *testing.T) {
	testSvc := getTestSvc()
	testPod := getTestPod()
	hostPort := 4001
	testPod.Spec.Containers[0].Ports = append(
		testPod.Spec.Containers[0].Ports,
		corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolTCP},
	)
	testData := setUp(t, newTestConfig(), testSvc, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort)
	assert.Equal(t, nplData[0].NodePort, hostPort)
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodAddHostPort creates a Pod with multiple host ports having same value but different protocol.
// It verifies that the Pod's NPL annotation is updated with host port, without allocating extra port
// from NPL pool. No NPL rule is required for this case.
func TestPodAddHostPortMultiProtocol(t *testing.T) {
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
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort)
	assert.Equal(t, nplData[0].NodePort, hostPort)
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodAddHostPortWrongProtocol creates a Pod with a host port but with protocol UDP instead of TCP.
// In this case, instead of using host port, a new port should be allocated from NPL port pool.
func TestPodAddHostPortWrongProtocol(t *testing.T) {
	testSvc := getTestSvc()
	testPod := getTestPod()
	hostPort := 4001
	testPod.Spec.Containers[0].Ports = append(
		testPod.Spec.Containers[0].Ports,
		corev1.ContainerPort{ContainerPort: int32(defaultPort), HostPort: int32(hostPort), Protocol: corev1.ProtocolUDP},
	)
	testData := setUp(t, newTestConfig(), testSvc, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort)
	assert.NotEqual(t, nplData[0].NodePort, hostPort)
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestTargetPortWithName creates a Service with target port name in string.
// A Pod with matching container port name is also created and it is verified that
// the port table is updated with desired NPL rule.
func TestTargetPortWithName(t *testing.T) {
	portName := "abcPort"
	testSvc := getTestSvcWithPortName(portName)
	testPod := getTestPod()
	testPod.Spec.Containers[0].Ports = append(
		testPod.Spec.Containers[0].Ports,
		corev1.ContainerPort{ContainerPort: int32(defaultPort), Name: portName, Protocol: corev1.ProtocolTCP},
	)
	testData := setUp(t, newTestConfig(), testSvc, testPod)
	defer testData.tearDown()

	_, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.True(t, testData.portTable.RuleExists(testPod.Status.PodIP, defaultPort))

	testSvc = getTestSvcWithPortName("wrongPort")
	testData.updateServiceOrFail(testSvc)
	_, err = testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(testPod.Status.PodIP, defaultPort))
}

// TestMultiplePods creates multiple Pods and verifies that NPL annotations for both Pods are
// updated correctly, along with the local port table.
func TestMultiplePods(t *testing.T) {
	testSvc := getTestSvc()
	testPod1 := getTestPod()
	testPod1.Name = "pod1"
	testPod1.Status.PodIP = "10.10.10.1"
	testPod2 := getTestPod()
	testPod2.Name = "pod2"
	testPod2.Status.PodIP = "10.10.10.2"
	testData := setUp(t, newTestConfig(), testSvc, testPod1, testPod2)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod1.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData1 := testData.checkAnnotationValue(value, defaultPort)
	assert.True(t, testData.portTable.RuleExists(testPod1.Status.PodIP, defaultPort))

	value, err = testData.pollForPodAnnotation(testPod2.Name, true)
	assert.NoError(t, err, "Poll for annotation check failed")
	nplData2 := testData.checkAnnotationValue(value, defaultPort)
	assert.True(t, testData.portTable.RuleExists(testPod2.Status.PodIP, defaultPort))

	assert.NotEqual(t, nplData1[0].NodePort, nplData2[0].NodePort)
}

func TestMultipleServicesSameBackendPod(t *testing.T) {
	testSvc1 := getTestSvc()
	testPod := getTestPod()
	testSvc2 := getTestSvc(9090)
	testSvc2.Name = "svc2"
	testData := setUp(t, newTestConfig(), testSvc1, testSvc2, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort, 9090)
	assert.True(t, testData.portTable.RuleExists(testPod.Status.PodIP, defaultPort))
	assert.True(t, testData.portTable.RuleExists(testPod.Status.PodIP, 9090))
	assert.NotEqual(t, nplData[0].NodePort, nplData[1].NodePort)
}

// TestInitInvalidPod simulates an agent reboot case. A Pod with an invalid NPL annotation is
// added, this invalid annotation should get cleaned up. And a proper NPL annotation should get
// added.
func TestInitInvalidPod(t *testing.T) {
	testSvc := getTestSvc()
	testPod := getTestPod()
	// assign an invalid annotation
	annotations := map[string]string{
		nplk8s.NPLAnnotationKey: "[{\"podPort\":53,\"nodeIP\":\"10.10.10.10\", \"nodePort\": 30000}]",
	}
	testPod.SetAnnotations(annotations)
	testData := setUp(t, newTestConfig(), testSvc, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	testData.checkAnnotationValue(value, defaultPort)
	assert.True(t, testData.portTable.RuleExists(testPod.Status.PodIP, defaultPort))
}

var (
	portTakenError = fmt.Errorf("Port taken")
)

// TestNodePortAlreadyBoundTo validates that when a port is already bound to, a different port will
// be selected for NPL.
func TestNodePortAlreadyBoundTo(t *testing.T) {
	testSvc := getTestSvc()
	testPod := getTestPod()
	testConfig := newTestConfig().withDefaultPortOpenerExpectations(false)
	testData := setUp(t, testConfig)
	defer testData.tearDown()

	var nodePort int
	gomock.InOrder(
		testData.mockPortOpener.EXPECT().OpenLocalPort(gomock.Any()).Return(nil, portTakenError),
		testData.mockPortOpener.EXPECT().OpenLocalPort(gomock.Any()).DoAndReturn(func(port int) (portcache.Closeable, error) {
			nodePort = port
			return &fakeSocket{}, nil
		}),
	)

	_, err := testData.k8sClient.CoreV1().Services(defaultNS).Create(context.TODO(), testSvc, metav1.CreateOptions{})
	require.NoError(t, err, "Service creation failed")

	_, err = testData.k8sClient.CoreV1().Pods(defaultNS).Create(context.TODO(), testPod, metav1.CreateOptions{})
	require.NoError(t, err, "Pod creation failed")

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	annotation := testData.checkAnnotationValue(value, defaultPort)[0] // length of slice is guaranteed to be correct at this stage
	assert.Equal(t, nodePort, annotation.NodePort)
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}
