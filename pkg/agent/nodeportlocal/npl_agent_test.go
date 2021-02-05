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

	nplk8s "github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"
	npltest "github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules/testing"
)

func newPortTable(c *gomock.Controller) *portcache.PortTable {
	ptable := portcache.PortTable{StartPort: 40000, EndPort: 45000}
	ptable.Table = make(map[int]portcache.NodePortData)

	mockTable := npltest.NewMockPodPortRules(c)
	mockTable.EXPECT().AddRule(gomock.Any(), gomock.Any()).AnyTimes()
	mockTable.EXPECT().DeleteRule(gomock.Any(), gomock.Any()).AnyTimes()

	ptable.PodPortRules = mockTable
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
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: int32(defaultPort),
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			HostIP: defaultHostIP,
			PodIP:  defaultPodIP,
		},
	}
}

func getTestSvc() *corev1.Service {
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
					Type:   intstr.Int,
					IntVal: defaultPort,
				},
			}},
		},
	}
}

type testData struct {
	*testing.T
	stopCh    chan struct{}
	ctrl      *gomock.Controller
	k8sClient *k8sfake.Clientset
	portTable *portcache.PortTable
	wg        sync.WaitGroup
}

func (data *testData) runWrapper(c *nplk8s.NPLController) {
	data.wg.Add(1)
	go func() {
		defer data.wg.Done()
		c.Run(data.stopCh)
	}()
}

func setUp(t *testing.T, objects ...runtime.Object) *testData {
	os.Setenv("NODE_NAME", defaultNodeName)

	mockCtrl := gomock.NewController(t)
	data := &testData{
		T:         t,
		stopCh:    make(chan struct{}),
		ctrl:      mockCtrl,
		k8sClient: k8sfake.NewSimpleClientset(objects...),
		portTable: newPortTable(mockCtrl),
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

func setUpWithTestServiceAndPod(t *testing.T) (*testData, *corev1.Service, *corev1.Pod) {
	testSvc := getTestSvc()
	testPod := getTestPod()

	testData := setUp(t, testSvc, testPod)

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
		} else {
			return !exists, nil
		}
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

// TestSvcUpdateAnnotation updates the Service spec to disabled NPL. It then verifies that the Pod's
// NPL annotation is removed and that the port table is updated.
func TestSvcUpdateAnnotation(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t)
	defer testData.tearDown()

	// Disable NPL.
	testSvc.Annotations = map[string]string{nplk8s.NPLEnabledAnnotationKey: "false"}
	testData.updateServiceOrFail(testSvc)

	// Check that annotation and the rule is removed.
	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestSvcRemoveAnnotation is the same as TestSvcUpdateAnnotation, but it deletes the NPL enabled
// annotation, instead of setting its value to false.
func TestSvcRemoveAnnotation(t *testing.T) {
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t)
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
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t)
	defer testData.tearDown()

	testSvc.Spec.Selector = map[string]string{"foo": "invalid-selector"}
	testData.updateServiceOrFail(testSvc)

	_, err := testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodUpdateSelectorLabel updates the Pod's labels so that the Pod is no longer selected by the
// Service. It then verifies that the Pod's NPL annotation is removed and that the port table is
// updated.
func TestPodUpdateSelectorLabel(t *testing.T) {
	testData, _, testPod := setUpWithTestServiceAndPod(t)
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
	testData, testSvc, testPod := setUpWithTestServiceAndPod(t)
	defer testData.tearDown()

	err := testData.k8sClient.CoreV1().Services(defaultNS).Delete(context.TODO(), testSvc.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Service deletion failed")
	t.Logf("successfully deleted Service: %s", testSvc.Name)

	_, err = testData.pollForPodAnnotation(testPod.Name, false)
	require.NoError(t, err, "Poll for annotation check failed")
	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
}

// TestPodUpdate verifies that any update in the Pod container port is reflected in Pod annotation
// and local port table.
func TestPodUpdate(t *testing.T) {
	testData, _, testPod := setUpWithTestServiceAndPod(t)
	defer testData.tearDown()

	newPort := 8080
	testPod.Spec.Containers[0].Ports[0].ContainerPort = int32(newPort)
	testData.updatePodOrFail(testPod)

	err := wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		updatedPod, err := testData.k8sClient.CoreV1().Pods(defaultNS).Get(context.TODO(), testPod.Name, metav1.GetOptions{})
		require.NoError(t, err, "Failed to get Pod")

		ann := updatedPod.GetAnnotations()
		var nplData []nplk8s.NPLAnnotation
		value, exists := ann[nplk8s.NPLAnnotationKey]
		if !exists {
			return false, nil
		}
		err = json.Unmarshal([]byte(value), &nplData)
		require.NoError(t, err, "Error when unmarshalling NPL annotation")
		t.Logf("Pod annotation: %v", nplData)

		if len(nplData) != 1 || nplData[0].PodPort != 8080 {
			return false, nil
		}
		return true, nil
	})
	assert.NoError(t, err, "Error when polling for annotation update")

	assert.False(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, newPort), true)
}

// TestPodDelete verifies that when a Pod gets deleted, the corresponding entry gets deleted from
// local port table as well.
func TestPodDelete(t *testing.T) {
	testData, _, testPod := setUpWithTestServiceAndPod(t)
	defer testData.tearDown()

	err := testData.k8sClient.CoreV1().Pods(defaultNS).Delete(context.TODO(), testPod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Pod deletion failed")
	t.Logf("Successfully deleted Pod: %s", testPod.Name)

	err = wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		return !testData.portTable.RuleExists(defaultPodIP, defaultPort), nil
	})
	assert.NoError(t, err, "Error when polling for port table update")
}

// TestPodAddMultiPort creates a Pod with multiple ports and verifies that the Pod's NPL annotation
// and the local port table are updated correctly.
func TestPodAddMultiPort(t *testing.T) {
	testSvc := getTestSvc()
	testPod := getTestPod()
	newPort := 90
	testPod.Spec.Containers[0].Ports = append(
		testPod.Spec.Containers[0].Ports,
		corev1.ContainerPort{ContainerPort: int32(newPort)},
	)
	testData := setUp(t, testSvc, testPod)
	defer testData.tearDown()

	value, err := testData.pollForPodAnnotation(testPod.Name, true)
	require.NoError(t, err, "Poll for annotation check failed")
	nplData := testData.checkAnnotationValue(value, defaultPort, newPort)
	assert.NotEqual(t, nplData[0].NodePort, nplData[1].NodePort)
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, defaultPort))
	assert.True(t, testData.portTable.RuleExists(defaultPodIP, newPort))
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
	testData := setUp(t, testSvc, testPod1, testPod2)
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
