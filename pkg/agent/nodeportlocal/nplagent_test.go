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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"
	npltest "github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules/testing"
	"github.com/vmware-tanzu/antrea/pkg/signals"
)

func NewPortTable(c *gomock.Controller) *portcache.PortTable {
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

var kubeClient *k8sfake.Clientset
var portTable *portcache.PortTable

func getTestPod() corev1.Pod {
	return corev1.Pod{
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

func getTestSvc() corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultSvcName,
			Namespace: defaultNS,
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

func TestMain(t *testing.T) {
	os.Setenv("NODE_NAME", defaultNodeName)
	kubeClient = k8sfake.NewSimpleClientset()
	mockCtrl := gomock.NewController(t)
	portTable = NewPortTable(mockCtrl)

	// informerFactory is initialised and started from cmd/antrea-agent/agent.go
	informerFactory := informers.NewSharedInformerFactory(kubeClient, resyncPeriod)

	c, _ := InitController(kubeClient, informerFactory, portTable, defaultNodeName)
	stopCh := signals.RegisterSignalHandlers()

	go c.Run(stopCh)
	informerFactory.Start(stopCh)
}

func pollForPodAnnotation(r *require.Assertions, podName string, found bool) (string, error) {
	var data string
	var exists bool
	err := wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		updatedPod, err := kubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), podName, metav1.GetOptions{})
		r.Nil(err, "Failed to get Pod")
		ann := updatedPod.GetAnnotations()
		data, exists = ann[k8s.NPLAnnotationKey]
		if found {
			return exists, nil
		} else {
			return !exists, nil
		}
	})

	return data, err
}

// Add a Service (proper annotation) and Pod pair, update Service with bad
// annotation value and check for Pod annotation and port cache entry removal.
func TestSvcUpdateAnnotation(t *testing.T) {
	var data string

	a := assert.New(t)
	r := require.New(t)

	servicePodName := "pod-svc"

	testSvc := getTestSvc()
	testSvc.Name = servicePodName
	testSvc.Spec.Selector[defaultAppSelectorKey] = servicePodName
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	s, err := kubeClient.CoreV1().Services(defaultNS).Create(context.TODO(), &testSvc, metav1.CreateOptions{})
	r.Nil(err, "Service creation failed")
	t.Logf("successfully created Service: %v", s)

	testPod := getTestPod()
	testPod.Name = servicePodName
	testPod.Labels[defaultAppSelectorKey] = servicePodName
	p, err := kubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod, metav1.CreateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	data, err = pollForPodAnnotation(r, servicePodName, true)
	r.Nil(err, "Poll for annotation check failed")

	var nplData []k8s.NPLAnnotation
	json.Unmarshal([]byte(data), &nplData)

	a.Len(nplData, 1)
	a.Equal(nplData[0].NodeIP, defaultHostIP)
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	// Update Service with bad annotation value.
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "false"}
	testSvc.ResourceVersion = "2"
	s, err = kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %s", s.Name)

	// Check that annotation and the rule is removed.
	_, err = pollForPodAnnotation(r, servicePodName, false)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
}

// Update existing Service with proper annotation to get Pod annotation and port
// cache entry back, remove annotation from Service.
func TestSvcRemoveAnnotation(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	servicePodName := "pod-svc"

	testSvc := getTestSvc()
	testSvc.Name = servicePodName
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	testSvc.Spec.Selector[defaultAppSelectorKey] = servicePodName
	testSvc.ResourceVersion = "3"
	s, err := kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %s", s.Name)

	_, err = pollForPodAnnotation(r, servicePodName, true)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	testSvc.Annotations = make(map[string]string)
	testSvc.ResourceVersion = "4"
	s, err = kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %v", s)

	_, err = pollForPodAnnotation(r, servicePodName, false)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
}

func TestSvcUpdateSelector(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	servicePodName := "pod-svc"

	testSvc := getTestSvc()
	testSvc.Name = servicePodName
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	testSvc.Spec.Selector[defaultAppSelectorKey] = servicePodName
	testSvc.ResourceVersion = "5"
	s, err := kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %s", s.Name)

	_, err = pollForPodAnnotation(r, servicePodName, true)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	testSvc.Spec.Selector = map[string]string{"foo": "invalid-selector"}
	testSvc.ResourceVersion = "6"
	s, err = kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %v", s)

	_, err = pollForPodAnnotation(r, servicePodName, false)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
}

func TestPodUpdateSelectorLabel(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	servicePodName := "pod-svc"

	testSvc := getTestSvc()
	testSvc.Name = servicePodName
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	testSvc.Spec.Selector[defaultAppSelectorKey] = servicePodName
	testSvc.ResourceVersion = "7"
	s, err := kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %s", s.Name)

	_, err = pollForPodAnnotation(r, servicePodName, true)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	testPod := getTestPod()
	testPod.Name = servicePodName
	testPod.Labels["invalid-label-key"] = servicePodName
	testPod.ResourceVersion = "2"
	p, err := kubeClient.CoreV1().Pods(defaultNS).Update(context.TODO(), &testPod, metav1.UpdateOptions{})
	r.Nil(err, "Pod update failed")
	t.Logf("successfully updated Pod: %v", p)

	_, err = pollForPodAnnotation(r, servicePodName, false)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
}

// Update existing Service with proper annotation to get Pod annotation and port
// cache entry back, delete Service.
func TestDeleteSvc(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	servicePodName := "pod-svc"

	testSvc := getTestSvc()
	testSvc.Name = servicePodName
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	testSvc.Spec.Selector[defaultAppSelectorKey] = servicePodName
	testSvc.ResourceVersion = "7"
	s, err := kubeClient.CoreV1().Services(defaultNS).Update(context.TODO(), &testSvc, metav1.UpdateOptions{})
	r.Nil(err, "Service update failed")
	t.Logf("successfully updated Service: %s", s.Name)

	testPod := getTestPod()
	testPod.Name = servicePodName
	testPod.Labels[defaultAppSelectorKey] = servicePodName
	testPod.ResourceVersion = "3"
	p, err := kubeClient.CoreV1().Pods(defaultNS).Update(context.TODO(), &testPod, metav1.UpdateOptions{})
	r.Nil(err, "Pod update failed")
	t.Logf("successfully updated Pod: %v", p)

	_, err = pollForPodAnnotation(r, servicePodName, true)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	err = kubeClient.CoreV1().Services(defaultNS).Delete(context.TODO(), servicePodName, metav1.DeleteOptions{})
	r.Nil(err, "Service deletion failed")
	t.Logf("successfully deleted Service: %s", servicePodName)

	_, err = pollForPodAnnotation(r, servicePodName, false)
	r.Nil(err, "Poll for annotation check failed")
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
}

// Add a new Pod with fake k8s client and verify that NPL annotation gets updated
// and an entry gets added in the local port cache.
func TestPodAdd(t *testing.T) {
	var data string

	a := assert.New(t)
	r := require.New(t)

	testSvc := getTestSvc()
	testSvc.Annotations = map[string]string{k8s.NPLEnabledAnnotationKey: "true"}
	_, err := kubeClient.CoreV1().Services(defaultNS).Create(context.TODO(), &testSvc, metav1.CreateOptions{})
	r.Nil(err, "Service creation failed")

	testPod := getTestPod()
	p, err := kubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod, metav1.CreateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	data, err = pollForPodAnnotation(r, defaultPodName, true)
	r.Nil(err, "Poll for annotation check failed")

	var nplData []k8s.NPLAnnotation
	json.Unmarshal([]byte(data), &nplData)

	a.Len(nplData, 1)
	a.Equal(nplData[0].NodeIP, defaultHostIP)
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)
}

// Test that any update in the Pod container port is reflected in Pod annotation and local port cache.
func TestPodUpdate(t *testing.T) {
	var ann map[string]string
	var nplData []k8s.NPLAnnotation
	var data string

	a := assert.New(t)
	r := require.New(t)

	testPod := getTestPod()
	testPod.Spec.Containers[0].Ports[0].ContainerPort = 8080
	testPod.ResourceVersion = "2"
	p, err := kubeClient.CoreV1().Pods(defaultNS).Update(context.TODO(), &testPod, metav1.UpdateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	err = wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		updatedPod, err := kubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), defaultPodName, metav1.GetOptions{})
		r.Nil(err, "Failed to get Pod")
		ann = updatedPod.GetAnnotations()
		data, _ = ann[k8s.NPLAnnotationKey]
		json.Unmarshal([]byte(data), &nplData)
		t.Logf("Pod annotation: %v", nplData)
		if len(nplData) != 1 {
			return false, nil
		}
		if nplData[0].PodPort == 8080 {
			return true, nil
		}
		return false, nil
	})
	r.Nil(err, "Poll for annotation check failed")

	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), false)
	a.Equal(portTable.RuleExists(defaultPodIP, 8080), true)
}

// Make sure that when a Pod gets deleted, corresponding entry gets deleted from local port cache also
func TestPodDel(t *testing.T) {
	r := require.New(t)

	err := kubeClient.CoreV1().Pods(defaultNS).Delete(context.TODO(), defaultPodName, metav1.DeleteOptions{})
	r.Nil(err, "Pod deletion failed")
	t.Logf("successfully deleted Pod: %s", defaultPodName)

	err = wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		return !portTable.RuleExists(defaultPodIP, 8080), nil
	})
	r.Nil(err, "Poll for rule check failed")
}

// Create a Pod with multiple ports and verify that Pod annotation and local port cache are updated correctly
func TestPodAddMultiPort(t *testing.T) {
	var data string

	a := assert.New(t)
	r := require.New(t)

	testPod := getTestPod()
	newPort := corev1.ContainerPort{ContainerPort: 90}
	testPod.Spec.Containers[0].Ports = append(testPod.Spec.Containers[0].Ports, newPort)
	p, err := kubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod, metav1.CreateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	data, err = pollForPodAnnotation(r, defaultPodName, true)
	r.Nil(err, "Poll for annotation check failed")

	var nplData []k8s.NPLAnnotation
	err = wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		json.Unmarshal([]byte(data), &nplData)
		if len(nplData) == 2 {
			return true, nil
		}
		return false, nil
	})
	r.Nil(err, "Poll for annotation length check failed")

	a.Equal(nplData[0].NodeIP, defaultHostIP)
	a.Equal(nplData[0].PodPort, defaultPort)
	a.Equal(portTable.RuleExists(defaultPodIP, defaultPort), true)

	a.Equal(nplData[1].NodeIP, defaultHostIP)
	a.Equal(nplData[1].PodPort, 90)
	a.Equal(portTable.RuleExists(defaultPodIP, 90), true)
}

// Create Multiple Pods and test that annotations for both the Pods are updated correctly
// and local port cache is updated accordingly
func TestAddMultiplePods(t *testing.T) {
	var data string

	a := assert.New(t)
	r := require.New(t)

	testPod1 := getTestPod()
	testPod1.Name = "pod1"
	testPod1.Status.PodIP = "10.10.10.1"
	p, err := kubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod1, metav1.CreateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	testPod2 := getTestPod()
	testPod2.Name = "pod2"
	testPod2.Status.PodIP = "10.10.10.2"
	p, err = kubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod2, metav1.CreateOptions{})
	r.Nil(err, "Pod creation failed")
	t.Logf("successfully created Pod: %v", p)

	data, err = pollForPodAnnotation(r, testPod1.Name, true)
	r.Nil(err, "Poll for annotation check failed")

	var nplData []k8s.NPLAnnotation
	json.Unmarshal([]byte(data), &nplData)

	a.Len(nplData, 1)
	a.Equal(nplData[0].NodeIP, defaultHostIP)
	a.Equal(nplData[0].PodPort, defaultPort)
	a.Equal(portTable.RuleExists(testPod1.Status.PodIP, defaultPort), true)

	data, err = pollForPodAnnotation(r, testPod2.Name, true)
	r.Nil(err, "Poll for annotation check failed")

	json.Unmarshal([]byte(data), &nplData)

	a.Len(nplData, 1)
	a.Equal(nplData[0].NodeIP, defaultHostIP)
	a.Equal(nplData[0].PodPort, defaultPort)
	a.Equal(portTable.RuleExists(testPod2.Status.PodIP, defaultPort), true)
}
