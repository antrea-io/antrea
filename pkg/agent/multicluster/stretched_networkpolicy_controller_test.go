// Copyright 2022 Antrea Authors
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

package multicluster

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	antreatypes "antrea.io/antrea/pkg/agent/types"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
)

const (
	interval = 10 * time.Millisecond
	timeout  = 2 * time.Second
)

type fakeStretchedNetworkPolicyController struct {
	*StretchedNetworkPolicyController
	clientset         *fake.Clientset
	mcClient          *mcfake.Clientset
	informerFactory   informers.SharedInformerFactory
	mcInformerFactory mcinformers.SharedInformerFactory
	ofClient          *oftest.MockClient
	ovsClient         *ovsconfigtest.MockOVSBridgeClient
	interfaceStore    *interfacestoretest.MockInterfaceStore
	podUpdateChannel  *channel.SubscribableChannel
}

func newStretchedNetworkPolicyController(t *testing.T, clientset *fake.Clientset, mcClient *mcfake.Clientset) *fakeStretchedNetworkPolicyController {
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "test-node").String()
	}
	podInformer := coreinformers.NewFilteredPodInformer(
		clientset,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
		listOptions,
	)
	nsInformer := informerFactory.Core().V1().Namespaces()
	mcInformerFactory := mcinformers.NewSharedInformerFactory(mcClient, 60*time.Second)
	labelIDInformer := mcInformerFactory.Multicluster().V1alpha1().LabelIdentities()

	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	interfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	c := NewMCAgentStretchedNetworkPolicyController(
		ofClient,
		interfaceStore,
		podInformer,
		nsInformer,
		labelIDInformer,
		podUpdateChannel,
	)
	return &fakeStretchedNetworkPolicyController{
		StretchedNetworkPolicyController: c,
		clientset:                        clientset,
		mcClient:                         mcClient,
		informerFactory:                  informerFactory,
		mcInformerFactory:                mcInformerFactory,
		ofClient:                         ofClient,
		ovsClient:                        ovsClient,
		interfaceStore:                   interfaceStore,
		podUpdateChannel:                 podUpdateChannel,
	}
}

var (
	interfaceConfig = interfacestore.InterfaceConfig{
		InterfaceName: "foo",
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 2,
		},
		IPs: []net.IP{[]byte("1.1.1.1")},
	}
	unknownLabelIdentity = openflow.UnknownLabelIdentity
)

func TestEnqueueAllPods(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: "ns",
			Labels: map[string]string{
				"foo": "bar1",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	labelIdentity := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity1",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar1",
			ID:    1,
		},
	}

	clientset := fake.NewSimpleClientset(ns, pod)
	mcClient := mcfake.NewSimpleClientset(labelIdentity)
	c := newStretchedNetworkPolicyController(t, clientset, mcClient)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	go c.podInformer.Run(stopCh)
	if err := waitForPodRealized(c.podLister, pod); err != nil {
		t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod.Namespace, pod.Name, err)
	}
	if err := waitForLabelIdentityRealized(c, labelIdentity); err != nil {
		t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity.Name, err)
	}
	c.enqueueAllPods()

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity.Spec.ID)).Times(1)
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestStretchedNetworkPolicyControllerPodEvent(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: "ns",
			Labels: map[string]string{
				"foo": "bar1",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	labelIdentity1 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity1",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar1",
			ID:    1,
		},
	}
	labelIdentity2 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity2",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar2",
			ID:    2,
		},
	}

	clientset := fake.NewSimpleClientset()
	mcClient := mcfake.NewSimpleClientset()
	c := newStretchedNetworkPolicyController(t, clientset, mcClient)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	go c.podInformer.Run(stopCh)
	go c.podUpdateChannel.Run(stopCh)

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)
		c.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
		if err := waitForNSRealized(c, ns); err != nil {
			t.Errorf("Error when waiting for Namespace '%s' to be realized, err: %v", ns.Name, err)
		}

		// Create a Pod whose LabelIdentity doesn't exist.
		c.clientset.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, pod); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod.Namespace, pod.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&unknownLabelIdentity)).Times(1)
		c.podUpdateChannel.Notify(toPodAddEvent(pod))
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity1.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity1.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)

		// Delete a Pod.
		c.clientset.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})

		// Create a Pod whose LabelIdentity already exist.
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity1, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity1); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity1.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.clientset.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, pod); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod.Namespace, pod.Name, err)
		}
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity1.Spec.ID)).Times(1)
		c.podUpdateChannel.Notify(toPodAddEvent(pod))
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity1.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity1.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)

		// Update Pod label.
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity2, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity2); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity2.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		pod.Labels["foo"] = "bar2"
		c.clientset.CoreV1().Pods(pod.Namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
		if err := waitForPodLabelUpdate(c.podLister, pod); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", pod.Namespace, pod.Name, err)
		}
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity2.Spec.ID)).Times(1)
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity2.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity2.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestStretchedNetworkPolicyControllerNSEvent(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "ns",
			Labels: map[string]string{
				"foo": "bar1",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "ns",
			Labels: map[string]string{
				"foo": "bar2",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	labelIdentity1 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity1",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar1",
			ID:    1,
		},
	}
	labelIdentity2 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity2",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar2",
			ID:    2,
		},
	}
	labelIdentity3 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity3",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=prod,kubernetes.io/metadata.name=ns&pod:foo=bar1",
			ID:    3,
		},
	}
	labelIdentity4 := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity4",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=prod,kubernetes.io/metadata.name=ns&pod:foo=bar2",
			ID:    4,
		},
	}

	clientset := fake.NewSimpleClientset()
	mcClient := mcfake.NewSimpleClientset()
	c := newStretchedNetworkPolicyController(t, clientset, mcClient)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	go c.podInformer.Run(stopCh)
	go c.podUpdateChannel.Run(stopCh)

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)

		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity1, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity1); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized: %v", labelIdentity1.Name, err)
		}
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity2, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity2); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity2.Name, err)
		}
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity3, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity3); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity3.Name, err)
		}
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity4, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity4); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity4.Name, err)
		}

		c.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
		if err := waitForNSRealized(c, ns); err != nil {
			t.Errorf("Error when waiting for Namespace '%s' to be realized, err: %v", ns.Name, err)
		}

		c.clientset.CoreV1().Pods(pod1.Namespace).Create(context.TODO(), pod1, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, pod1); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod1.Namespace, pod1.Name, err)
		}
		c.clientset.CoreV1().Pods(pod2.Namespace).Create(context.TODO(), pod2, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, pod2); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod2.Namespace, pod2.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod1.Name, pod1.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod2.Name, pod2.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity1.Spec.ID)).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity2.Spec.ID)).Times(1)
		c.podUpdateChannel.Notify(toPodAddEvent(pod1))
		c.processNextWorkItem()
		c.podUpdateChannel.Notify(toPodAddEvent(pod2))
		c.processNextWorkItem()

		// Update Namespace label.
		ns.Labels["env"] = "prod"
		c.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod1.Name, pod1.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod2.Name, pod2.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity3.Spec.ID)).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity4.Spec.ID)).Times(1)
		c.processNextWorkItem()
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{
			{Name: pod1.Name, Namespace: pod1.Namespace}: labelIdentity3.Spec.Label,
			{Name: pod2.Name, Namespace: pod2.Namespace}: labelIdentity4.Spec.Label,
		}, c.podToLabel)
		assert.Equal(t, map[string]podSet{
			labelIdentity3.Spec.Label: {types.NamespacedName{Name: pod1.Name, Namespace: pod1.Namespace}: struct{}{}},
			labelIdentity4.Spec.Label: {types.NamespacedName{Name: pod2.Name, Namespace: pod2.Namespace}: struct{}{}},
		}, c.labelToPods)
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestStretchedNetworkPolicyControllerLabelIdentityEvent(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: "ns",
			Labels: map[string]string{
				"foo": "bar1",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	labelIdentity := &v1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelIdentity",
		},
		Spec: v1alpha1.LabelIdentitySpec{
			Label: "ns:env=test,kubernetes.io/metadata.name=ns&pod:foo=bar1",
			ID:    1,
		},
	}
	clientset := fake.NewSimpleClientset()
	mcClient := mcfake.NewSimpleClientset()
	c := newStretchedNetworkPolicyController(t, clientset, mcClient)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	go c.podInformer.Run(stopCh)
	go c.podUpdateChannel.Run(stopCh)

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)
		c.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
		if err := waitForNSRealized(c, ns); err != nil {
			t.Errorf("Error when waiting for Namespace '%s' to be realized, err: %v", ns.Name, err)
		}

		c.clientset.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, pod); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod.Namespace, pod.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&unknownLabelIdentity)).Times(1)
		c.podUpdateChannel.Notify(toPodAddEvent(pod))
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)

		// Create LabelIdentity
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Create(context.TODO(), labelIdentity, metav1.CreateOptions{})
		if err := waitForLabelIdentityRealized(c, labelIdentity); err != nil {
			t.Errorf("Error when waiting for LabelIdentity '%s' to be realized, err: %v", labelIdentity.Name, err)
		}
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity.Spec.ID)).Times(1)
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)

		// Update LabelIdentity
		labelIdentity.Spec.ID = 2
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Update(context.TODO(), labelIdentity, metav1.UpdateOptions{})
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&labelIdentity.Spec.ID)).Times(1)
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)

		// Delete LabelIdentity
		c.mcClient.MulticlusterV1alpha1().LabelIdentities().Delete(context.TODO(), labelIdentity.Name, metav1.DeleteOptions{})
		c.interfaceStore.EXPECT().GetContainerInterfacesByPod(pod.Name, pod.Namespace).Return([]*interfacestore.InterfaceConfig{&interfaceConfig}).Times(1)
		c.ofClient.EXPECT().InstallPodFlows(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(&unknownLabelIdentity)).Times(1)
		c.processNextWorkItem()
		assert.Equal(t, map[types.NamespacedName]string{{Name: pod.Name, Namespace: pod.Namespace}: labelIdentity.Spec.Label}, c.podToLabel)
		assert.Equal(t, map[string]podSet{labelIdentity.Spec.Label: {types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}: struct{}{}}}, c.labelToPods)
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func toPodAddEvent(pod *corev1.Pod) antreatypes.PodUpdate {
	return antreatypes.PodUpdate{
		PodNamespace: pod.Namespace,
		PodName:      pod.Name,
		IsAdd:        true,
	}
}

func waitForPodRealized(podLister v1.PodLister, pod *corev1.Pod) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		_, err := podLister.Pods(pod.Namespace).Get(pod.Name)
		if err != nil {
			return false, nil
		}
		return true, err
	})
}

func waitForPodLabelUpdate(podLister v1.PodLister, pod *corev1.Pod) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		getPod, err := podLister.Pods(pod.Namespace).Get(pod.Name)
		if err != nil || !reflect.DeepEqual(pod.Labels, getPod.Labels) {
			return false, nil
		}
		return true, err
	})
}

func waitForNSRealized(c *fakeStretchedNetworkPolicyController, ns *corev1.Namespace) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		_, err := c.namespaceLister.Get(ns.Name)
		if err != nil {
			return false, nil
		}
		return true, err
	})
}

func waitForLabelIdentityRealized(c *fakeStretchedNetworkPolicyController, labelIdentity *v1alpha1.LabelIdentity) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		_, err := c.labelIdentityLister.Get(labelIdentity.Name)
		if err != nil {
			return false, nil
		}
		return true, err
	})
}
