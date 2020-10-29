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

package nplagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/portcache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// Mock PortPortRule for tests to simulate IPTable
// Currently the functions always return true to adhere to the interface requirement
type PPRTest struct {
}

func (PPRTest) Init() (bool, error) {
	return true, nil
}

func (PPRTest) AddRule(port int, podip string) (bool, error) {
	return true, nil
}

func (PPRTest) DeleteRule(port int, podip string) (bool, error) {
	return true, nil
}

func (PPRTest) SyncState(podPort map[int]string) bool {
	return true
}

func (PPRTest) GetAllRules(podPort map[int]string) (bool, error) {
	return true, nil
}

func (PPRTest) DeleteAllRules() (bool, error) {
	return true, nil
}

type nplAnnotation struct {
	Podport  string
	Nodeip   string
	Nodeport string
}

func NewPortTable() *portcache.PortTable {
	ptable := portcache.PortTable{StartPort: 40000, EndPort: 45000}
	ptable.Table = make(map[int]portcache.NodePortData)
	ptable.PodPortRules = &PPRTest{}
	return &ptable
}

var defaultPodName = "test-pod"
var defaultNS = "default"
var defaultNodeName = "test-node"
var defaultHostIP = "10.10.10.10"
var defaultPodIP = "192.168.32.10"
var defaultPort = 80

var kubeClient *k8sfake.Clientset
var c *k8s.Controller

func getTestPod() corev1.Pod {

	testPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultPodName,
			Namespace: defaultNS,
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
	return testPod
}

func TestMain(t *testing.T) {
	os.Setenv("HOSTNAME", defaultNodeName)
	kubeClient = k8sfake.NewSimpleClientset()

	informerFactory := informers.NewSharedInformerFactory(kubeClient, 5*time.Second)
	c = k8s.NewNPLController(kubeClient)

	c.PortTable = NewPortTable()
	c.SetupEventHandlers(informerFactory)
	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
}

// Add a new Pod with fake k8s client and verify that npl annotation gets updated
// and an entry gets added in the local port cache
func TestPodAdd(t *testing.T) {
	var ann map[string]string
	var data string
	var found bool

	g := gomega.NewGomegaWithT(t)

	testPod := getTestPod()
	p, err := c.KubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Pod creation failed with err: %v", err)
	}
	t.Logf("successfully created Pod: %v", p)

	g.Eventually(func() bool {
		updatedPod, err := c.KubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), defaultPodName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to update pod: %v", err)
		}
		ann = updatedPod.GetAnnotations()
		data, found = ann[lib.NPLEPAnnotation]
		return found
	}, 20*time.Second).Should(gomega.Equal(true))

	var nplData []nplAnnotation
	json.Unmarshal([]byte(data), &nplData)

	if len(nplData) != 1 {
		t.Fatalf("Expected npl annotation of length: 1, got: %d", len(nplData))
	}

	g.Expect(nplData[0].Nodeip).To(gomega.Equal(defaultHostIP))
	g.Expect(nplData[0].Podport).To(gomega.Equal(fmt.Sprint(defaultPort)))
	g.Expect(c.PortTable.RuleExists(defaultPodIP, defaultPort)).To(gomega.Equal(true))
}

// Test that any update in the Pod container port is reflected in pod annotation and local port cache
func TestPodUpdate(t *testing.T) {
	var ann map[string]string
	var nplData []nplAnnotation
	var data string

	g := gomega.NewGomegaWithT(t)

	testPod := getTestPod()
	testPod.Spec.Containers[0].Ports[0].ContainerPort = 8080
	testPod.ResourceVersion = "2"
	p, err := c.KubeClient.CoreV1().Pods(defaultNS).Update(context.TODO(), &testPod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Pod creation failed with err: %v", err)
	}
	t.Logf("successfully created Pod: %v", p)

	g.Eventually(func() string {
		updatedPod, err := c.KubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), defaultPodName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to update pod: %v", err)
		}
		ann = updatedPod.GetAnnotations()
		data, _ = ann[lib.NPLEPAnnotation]
		json.Unmarshal([]byte(data), &nplData)
		if len(nplData) != 1 {
			return ""
		}
		return nplData[0].Podport
	}, 20*time.Second).Should(gomega.Equal("8080"))
	g.Expect(c.PortTable.RuleExists(defaultPodIP, defaultPort)).To(gomega.Equal(false))
	g.Expect(c.PortTable.RuleExists(defaultPodIP, 8080)).To(gomega.Equal(true))
}

// Make sure that when a pod gets deleted, corresponding entry gets deleted from local port cache also
func TestPodDel(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	err := c.KubeClient.CoreV1().Pods(defaultNS).Delete(context.TODO(), defaultPodName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Pod deletion failed with err: %v", err)
	}
	t.Logf("successfully deleted Pod: %s", defaultPodName)

	g.Eventually(func() bool {
		return c.PortTable.RuleExists(defaultPodIP, 8080)
	}, 20*time.Second).Should(gomega.Equal(false))
}

// Create a pod with multiple ports and verify that pod annotation and local port cache are updated correctly
func TestPodAddMultiPort(t *testing.T) {
	var ann map[string]string
	var data string
	var found bool

	g := gomega.NewGomegaWithT(t)

	testPod := getTestPod()
	newPort := corev1.ContainerPort{ContainerPort: 90}
	testPod.Spec.Containers[0].Ports = append(testPod.Spec.Containers[0].Ports, newPort)
	p, err := c.KubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Pod creation failed with err: %v", err)
	}
	t.Logf("successfully created Pod: %v", p)

	g.Eventually(func() bool {
		updatedPod, err := c.KubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), defaultPodName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to update pod: %v", err)
		}
		ann = updatedPod.GetAnnotations()
		data, found = ann[lib.NPLEPAnnotation]
		return found
	}, 20*time.Second).Should(gomega.Equal(true))

	var nplData []nplAnnotation
	g.Eventually(func() int {
		json.Unmarshal([]byte(data), &nplData)
		return len(nplData)
	}, 20*time.Second).Should(gomega.Equal(2))

	g.Expect(nplData[0].Nodeip).To(gomega.Equal(defaultHostIP))
	g.Expect(nplData[0].Podport).To(gomega.Equal(fmt.Sprint(defaultPort)))
	g.Expect(c.PortTable.RuleExists(defaultPodIP, defaultPort)).To(gomega.Equal(true))

	g.Expect(nplData[1].Nodeip).To(gomega.Equal(defaultHostIP))
	g.Expect(nplData[1].Podport).To(gomega.Equal("90"))
	g.Expect(c.PortTable.RuleExists(defaultPodIP, 90)).To(gomega.Equal(true))
}

// Create Multiple Pods and test that annotations for both te pods are updated correctly
// and local port cache is updated accordingly
func TestAddMultiplePods(t *testing.T) {
	var ann map[string]string
	var data string
	var found bool

	g := gomega.NewGomegaWithT(t)

	testPod1 := getTestPod()
	testPod1.Name = "pod1"
	testPod1.Status.PodIP = "10.10.10.1"
	p, err := c.KubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod1, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Pod creation failed with err: %v", err)
	}
	t.Logf("successfully created Pod: %v", p)

	testPod2 := getTestPod()
	testPod2.Name = "pod2"
	testPod2.Status.PodIP = "10.10.10.2"
	p, err = c.KubeClient.CoreV1().Pods(defaultNS).Create(context.TODO(), &testPod2, metav1.CreateOptions{})
	if err != nil {
		t.Errorf("Pod creation failed with err: %v", err)
	}
	t.Logf("successfully created Pod: %v", p)

	g.Eventually(func() bool {
		updatedPod, err := c.KubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), testPod1.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to update pod: %v", err)
		}
		ann = updatedPod.GetAnnotations()
		data, found = ann[lib.NPLEPAnnotation]
		return found
	}, 20*time.Second).Should(gomega.Equal(true))

	var nplData []nplAnnotation
	json.Unmarshal([]byte(data), &nplData)

	if len(nplData) != 1 {
		t.Fatalf("Expected npl annotation of length: 1, got: %d", len(nplData))
	}

	g.Expect(nplData[0].Nodeip).To(gomega.Equal(defaultHostIP))
	g.Expect(nplData[0].Podport).To(gomega.Equal(fmt.Sprint(defaultPort)))
	g.Expect(c.PortTable.RuleExists(testPod1.Status.PodIP, defaultPort)).To(gomega.Equal(true))

	g.Eventually(func() bool {
		updatedPod, err := c.KubeClient.CoreV1().Pods(defaultNS).Get(context.TODO(), testPod2.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to update pod: %v", err)
		}
		ann = updatedPod.GetAnnotations()
		data, found = ann[lib.NPLEPAnnotation]
		return found
	}, 20*time.Second).Should(gomega.Equal(true))
	json.Unmarshal([]byte(data), &nplData)

	if len(nplData) != 1 {
		t.Fatalf("Expected npl annotation of length: 1, got: %d", len(nplData))
	}

	g.Expect(nplData[0].Nodeip).To(gomega.Equal(defaultHostIP))
	g.Expect(nplData[0].Podport).To(gomega.Equal(fmt.Sprint(defaultPort)))
	g.Expect(c.PortTable.RuleExists(testPod2.Status.PodIP, defaultPort)).To(gomega.Equal(true))
}
