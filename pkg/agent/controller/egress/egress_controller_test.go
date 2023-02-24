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

package egress

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/ipassigner"
	ipassignertest "antrea.io/antrea/pkg/agent/ipassigner/testing"
	"antrea.io/antrea/pkg/agent/memberlist"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	fakeLocalEgressIP1  = "1.1.1.1"
	fakeLocalEgressIP2  = "1.1.1.2"
	fakeRemoteEgressIP1 = "1.1.1.3"
	fakeNode            = "node1"
)

type fakeLocalIPDetector struct {
	localIPs sets.String
}

func (d *fakeLocalIPDetector) IsLocalIP(ip string) bool {
	return d.localIPs.Has(ip)
}

func (d *fakeLocalIPDetector) Run(stopCh <-chan struct{}) {
	<-stopCh
}

func (d *fakeLocalIPDetector) AddEventHandler(handler ipassigner.LocalIPEventHandler) {
	return
}

func (d *fakeLocalIPDetector) HasSynced() bool {
	return true
}

var _ ipassigner.LocalIPDetector = &fakeLocalIPDetector{}

type antreaClientGetter struct {
	clientset versioned.Interface
}

func (g *antreaClientGetter) GetAntreaClient() (versioned.Interface, error) {
	return g.clientset, nil
}

type fakeSingleNodeCluster struct {
	node string
}

func (c *fakeSingleNodeCluster) ShouldSelectIP(ip string, pool string, filters ...func(node string) bool) (bool, error) {
	selectedNode, err := c.SelectNodeForIP(ip, pool, filters...)
	if err != nil {
		return false, err
	}
	return selectedNode == c.node, nil
}

func (c *fakeSingleNodeCluster) SelectNodeForIP(ip, externalIPPool string, filters ...func(string) bool) (string, error) {
	for _, filter := range filters {
		if !filter(c.node) {
			return "", nil
		}
	}
	return c.node, nil
}

func (c *fakeSingleNodeCluster) AliveNodes() sets.String {
	return sets.NewString(c.node)
}

func (c *fakeSingleNodeCluster) AddClusterEventHandler(handler memberlist.ClusterNodeEventHandler) {}

func mockNewIPAssigner(ipAssigner ipassigner.IPAssigner) func() {
	originalNewIPAssigner := newIPAssigner
	newIPAssigner = func(_, _ string) (ipassigner.IPAssigner, error) {
		return ipAssigner, nil
	}
	return func() {
		newIPAssigner = originalNewIPAssigner
	}
}

type fakeController struct {
	*EgressController
	mockController     *gomock.Controller
	mockOFClient       *openflowtest.MockClient
	mockRouteClient    *routetest.MockInterface
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	informerFactory    informers.SharedInformerFactory
	mockIPAssigner     *ipassignertest.MockIPAssigner
	podUpdateChannel   *channel.SubscribableChannel
}

func newFakeController(t *testing.T, initObjects []runtime.Object) *fakeController {
	controller := gomock.NewController(t)

	mockOFClient := openflowtest.NewMockClient(controller)
	mockRouteClient := routetest.NewMockInterface(controller)
	mockIPAssigner := ipassignertest.NewMockIPAssigner(controller)
	defer mockNewIPAssigner(mockIPAssigner)()
	mockCluster := &fakeSingleNodeCluster{fakeNode}

	clientset := &fakeversioned.Clientset{}
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	k8sClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	localIPDetector := &fakeLocalIPDetector{localIPs: sets.NewString(fakeLocalEgressIP1, fakeLocalEgressIP2)}

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, "ns1", "pod1", 1)
	addPodInterface(ifaceStore, "ns2", "pod2", 2)
	addPodInterface(ifaceStore, "ns3", "pod3", 3)
	addPodInterface(ifaceStore, "ns4", "pod4", 4)

	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)

	egressController, _ := NewEgressController(mockOFClient,
		&antreaClientGetter{clientset},
		crdClient,
		ifaceStore,
		mockRouteClient,
		fakeNode,
		"eth0",
		mockCluster,
		egressInformer,
		nodeInformer,
		podUpdateChannel,
		255,
	)
	egressController.localIPDetector = localIPDetector
	return &fakeController{
		EgressController:   egressController,
		mockController:     controller,
		mockOFClient:       mockOFClient,
		mockRouteClient:    mockRouteClient,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		informerFactory:    informerFactory,
		mockIPAssigner:     mockIPAssigner,
		podUpdateChannel:   podUpdateChannel,
	}
}

func TestSyncEgress(t *testing.T) {
	tests := []struct {
		name                string
		maxEgressIPsPerNode int
		existingEgress      *crdv1a2.Egress
		newEgress           *crdv1a2.Egress
		existingEgressGroup *cpv1b2.EgressGroup
		newEgressGroup      *cpv1b2.EgressGroup
		newLocalIPs         sets.String
		expectedEgresses    []*crdv1a2.Egress
		expectedCalls       func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner)
	}{
		{
			name: "Local IP becomes non local",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			newLocalIPs: sets.NewString(),
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
			},
		},
		{
			name: "Non local IP becomes local",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			newLocalIPs: sets.NewString(fakeRemoteEgressIP1),
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
			},
		},
		{
			name: "Change from local Egress IP to another local one",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)

				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)
			},
		},
		{
			name: "Change from local Egress IP to a remote one",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
			},
		},
		{
			name: "Change from remote Egress IP to a local one",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
			},
		},
		{
			name: "Add an Egress having overlapping Pods",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)

				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)
			},
		},
		{
			name: "Add an Egress sharing the same Egress IP and having overlapping Pods",
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).Times(3)
			},
		},
		{
			name:                "Not exceed maxEgressIPsPerNode",
			maxEgressIPsPerNode: 1,
			// It's on this Node but doesn't occupy the quota as it's not allocated from an ExternalIPPool.
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: "external-ip-pool"},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: "external-ip-pool"},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP2).Times(2)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(2))
			},
		},
		{
			name:                "Exceed maxEgressIPsPerNode",
			maxEgressIPsPerNode: 1,
			existingEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: "external-ip-pool"},
			},
			newEgress: &crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: "external-ip-pool"},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
				},
			},
			expectedEgresses: []*crdv1a2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: "external-ip-pool"},
					Status:     crdv1a2.EgressStatus{EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: "external-ip-pool"},
					Status:     crdv1a2.EgressStatus{EgressNode: ""},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1).Times(2)
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, []runtime.Object{tt.existingEgress})
			defer c.mockController.Finish()

			if tt.maxEgressIPsPerNode > 0 {
				c.egressIPScheduler.maxEgressIPsPerNode = tt.maxEgressIPsPerNode
			}

			stopCh := make(chan struct{})
			defer close(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.informerFactory.Start(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.addEgressGroup(tt.existingEgressGroup)

			tt.expectedCalls(c.mockOFClient, c.mockRouteClient, c.mockIPAssigner)
			c.egressIPScheduler.schedule()
			err := c.syncEgress(tt.existingEgress.Name)
			assert.NoError(t, err)

			if tt.newEgress.Name == tt.existingEgress.Name {
				c.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), tt.newEgress, metav1.UpdateOptions{})
			} else {
				c.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), tt.newEgress, metav1.CreateOptions{})
			}

			c.addEgressGroup(tt.newEgressGroup)
			if tt.newLocalIPs != nil {
				c.localIPDetector = &fakeLocalIPDetector{localIPs: tt.newLocalIPs}
			}
			assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
				egress, _ := c.egressLister.Get(tt.newEgress.Name)
				return reflect.DeepEqual(egress, tt.newEgress), nil
			}))
			c.egressIPScheduler.schedule()
			err = c.syncEgress(tt.newEgress.Name)
			assert.NoError(t, err)
			// Call it one more time to ensure it's idempotent, no extra datapath calls are supposed to be made.
			err = c.syncEgress(tt.newEgress.Name)
			assert.NoError(t, err)
			for _, expectedEgress := range tt.expectedEgresses {
				gotEgress, err := c.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), expectedEgress.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, expectedEgress, gotEgress)
			}
		})
	}
}

func TestPodUpdateShouldSyncEgress(t *testing.T) {
	egress := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pendingPod", Namespace: "ns1"}},
		},
	}
	c := newFakeController(t, []runtime.Object{egress})
	defer c.mockController.Finish()
	stopCh := make(chan struct{})
	defer close(stopCh)
	go c.podUpdateChannel.Run(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	c.mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	c.addEgressGroup(egressGroup)
	require.Equal(t, 1, c.queue.Len())
	item, _ := c.queue.Get()
	require.Equal(t, egress.Name, item)
	require.NoError(t, c.syncEgress(item.(string)))
	c.queue.Done(item)

	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(10), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	// Mock CNIServer
	addPodInterface(c.ifaceStore, "ns1", "pendingPod", 10)
	ev := types.PodUpdate{
		PodName:      "pendingPod",
		PodNamespace: "ns1",
	}
	c.podUpdateChannel.Notify(ev)
	require.NoError(t, wait.PollImmediate(10*time.Millisecond, time.Second, func() (done bool, err error) {
		return c.queue.Len() == 1, nil
	}))
	item, _ = c.queue.Get()
	require.Equal(t, egress.Name, item)
	require.NoError(t, c.syncEgress(item.(string)))
	c.queue.Done(item)
}

func TestSyncOverlappingEgress(t *testing.T) {
	egress1 := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup1 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
		},
	}
	// egress2 shares a Pod with egress1.
	egress2 := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeRemoteEgressIP1},
	}
	egressGroup2 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
		},
	}
	// egress3 shares a Pod with egress1 and has the same EgressIP.
	egress3 := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup3 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
			{Pod: &cpv1b2.PodReference{Name: "pod4", Namespace: "ns4"}},
		},
	}
	c := newFakeController(t, []runtime.Object{egress1, egress2, egress3})
	defer c.mockController.Finish()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.addEgressGroup(egressGroup1)
	c.addEgressGroup(egressGroup2)
	c.addEgressGroup(egressGroup3)
	checkQueueItemExistence(t, c.queue, egress1.Name, egress2.Name, egress3.Name)

	c.mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err := c.syncEgress(egress1.Name)
	assert.NoError(t, err)

	// egress2's IP is not local and pod1 has enforced egress1, so only one Pod SNAT flow is expected.
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
	err = c.syncEgress(egress2.Name)
	assert.NoError(t, err)

	// egress3 shares the same IP as egress1 and pod2 has enforced egress1, so only one Pod SNAT flow is expected.
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(4), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err = c.syncEgress(egress3.Name)
	assert.NoError(t, err)

	// After deleting egress1, pod1 and pod2 no longer enforces egress1. The Egress IP shouldn't be released as egress3
	// is still referring to it.
	// egress2 and egress3 are expected to be triggered for resync.
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
	c.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress1.Name, metav1.DeleteOptions{})
	assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (bool, error) {
		_, err := c.egressLister.Get(egress1.Name)
		return err != nil, nil
	}))
	checkQueueItemExistence(t, c.queue, egress1.Name)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err = c.syncEgress(egress1.Name)
	assert.NoError(t, err)
	checkQueueItemExistence(t, c.queue, egress2.Name, egress3.Name)

	// pod1 is expected to enforce egress2.
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
	err = c.syncEgress(egress2.Name)
	assert.NoError(t, err)

	// pod2 is expected to enforce egress3.
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err = c.syncEgress(egress3.Name)
	assert.NoError(t, err)

	// After deleting egress2, pod1 and pod3 no longer enforces any Egress.
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(3))
	c.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress2.Name, metav1.DeleteOptions{})
	c.mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
	assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (bool, error) {
		_, err := c.egressLister.Get(egress2.Name)
		return err != nil, nil
	}))
	checkQueueItemExistence(t, c.queue, egress2.Name)
	err = c.syncEgress(egress2.Name)
	assert.NoError(t, err)
	require.Equal(t, 0, c.queue.Len())

	// After deleting egress3, pod2 and pod4 no longer enforces any Egress. The Egress IP should be released.
	c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
	c.mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(4))
	c.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress3.Name, metav1.DeleteOptions{})
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (bool, error) {
		_, err := c.egressLister.Get(egress3.Name)
		return err != nil, nil
	}))
	checkQueueItemExistence(t, c.queue, egress3.Name)
	err = c.syncEgress(egress3.Name)
	assert.NoError(t, err)
	require.Equal(t, 0, c.queue.Len())

	assert.Len(t, c.egressBindings, 0)
	assert.Len(t, c.egressStates, 0)
	assert.Len(t, c.egressIPStates, 0)
}

func addPodInterface(ifaceStore interfacestore.InterfaceStore, podNamespace, podName string, ofPort int32) {
	containerName := k8s.NamespacedName(podNamespace, podName)
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
	})
}

func TestUpdateEgressStatus(t *testing.T) {
	getError := fmt.Errorf("fake get Egress error")
	updateConflictError := &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonConflict, Message: "update Egress conflict"}}
	updateError := fmt.Errorf("update Egress error")
	tests := []struct {
		name                 string
		updateErrorNum       int
		updateError          error
		getErrorNum          int
		expectedUpdateCalled int
		expectedGetCalled    int
		expectedError        error
	}{
		{
			name:                 "succeed immediately",
			updateErrorNum:       0,
			updateError:          nil,
			getErrorNum:          0,
			expectedUpdateCalled: 1,
			expectedGetCalled:    0,
			expectedError:        nil,
		},
		{
			name:                 "succeed after one update conflict failure",
			updateErrorNum:       1,
			updateError:          updateConflictError,
			getErrorNum:          0,
			expectedUpdateCalled: 2,
			expectedGetCalled:    1,
			expectedError:        nil,
		},
		{
			name:                 "fail after one update failure",
			updateErrorNum:       1,
			updateError:          updateError,
			getErrorNum:          0,
			expectedUpdateCalled: 1,
			expectedGetCalled:    0,
			expectedError:        updateError,
		},
		{
			name:                 "fail after one update conflict failure and one get failure",
			updateErrorNum:       1,
			updateError:          updateConflictError,
			getErrorNum:          1,
			expectedUpdateCalled: 1,
			expectedGetCalled:    1,
			expectedError:        getError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			egress := crdv1a2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
			}
			fakeClient := &fakeversioned.Clientset{}
			getCalled := 0
			fakeClient.AddReactor("get", "egresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
				getCalled += 1
				if getCalled <= tt.getErrorNum {
					return true, nil, getError
				}
				return true, &egress, nil
			})
			updateCalled := 0
			fakeClient.AddReactor("update", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateCalled += 1
				if updateCalled <= tt.updateErrorNum {
					return true, nil, tt.updateError
				}
				return true, &egress, nil
			})

			c := &EgressController{crdClient: fakeClient, nodeName: fakeNode}
			_, err := c.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), &egress, metav1.CreateOptions{})
			assert.NoError(t, err)
			err = c.updateEgressStatus(&egress, true)
			if err != tt.expectedError {
				t.Errorf("Update Egress error not match, got: %v, expected: %v", err, tt.expectedError)
			}
			assert.Equal(t, tt.expectedGetCalled, getCalled, "Get called num not match")
			assert.Equal(t, tt.expectedUpdateCalled, updateCalled, "Update called num not match")
		})
	}
}

func TestGetEgress(t *testing.T) {
	egress := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
		},
	}

	c := newFakeController(t, []runtime.Object{egress})
	defer c.mockController.Finish()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.addEgressGroup(egressGroup)
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err := c.syncEgress(egress.Name)
	require.NoError(t, err)

	type args struct {
		ns      string
		podName string
	}
	tests := []struct {
		name               string
		args               args
		expectedEgressName string
		expectedErr        string
	}{
		{
			name: "local egress applied on a pod",
			args: args{
				ns:      "ns1",
				podName: "pod1",
			},
			expectedEgressName: "egressA",
		},
		{
			name: "no local egress applied on a pod",
			args: args{
				ns:      "ns2",
				podName: "pod2",
			},
			expectedErr: "no Egress applied to Pod ns2/pod2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEgressName, err := c.GetEgress(tt.args.ns, tt.args.podName)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedEgressName, gotEgressName)
		})
	}
}

func TestGetEgressIPByMark(t *testing.T) {
	egress := &crdv1a2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1a2.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}

	c := newFakeController(t, []runtime.Object{egress})
	defer c.mockController.Finish()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	err := c.syncEgress(egress.Name)
	require.NoError(t, err)

	tests := []struct {
		name             string
		mark             uint32
		expectedEgressIP string
		expectedErr      string
	}{
		{
			name:             "snatMark associated with local egressIP",
			mark:             uint32(1),
			expectedEgressIP: fakeLocalEgressIP1,
		},
		{
			name:        "snatMark not associated with any local egressIP",
			mark:        uint32(2),
			expectedErr: "no EgressIP associated with mark 2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEgressIP, err := c.GetEgressIPByMark(tt.mark)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedEgressIP, gotEgressIP)
		})
	}
}

func checkQueueItemExistence(t *testing.T, queue workqueue.RateLimitingInterface, items ...string) {
	t.Logf("queue len %d", queue.Len())
	require.Eventually(t, func() bool {
		return len(items) == queue.Len()
	}, time.Second, 10*time.Millisecond, "Didn't find enough items in the queue")
	expectedItems := sets.NewString(items...)
	actualItems := sets.NewString()
	for i := 0; i < len(expectedItems); i++ {
		key, _ := queue.Get()
		actualItems.Insert(key.(string))
		queue.Done(key)
	}
	assert.Equal(t, expectedItems, actualItems)
}
