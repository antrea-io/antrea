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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
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
	servicecidrtest "antrea.io/antrea/pkg/agent/servicecidr/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	fakeLocalEgressIP1  = "1.1.1.1"
	fakeLocalEgressIP2  = "1.1.1.2"
	fakeRemoteEgressIP1 = "1.1.1.3"
	fakeGatewayIP       = "1.1.0.1"
	fakeGatewayIP2      = "1.1.0.2"
	fakeNode            = "node1"
	fakeNode2           = "node2"
	fakeExternalIPPool  = "external-ip-pool"
)

var (
	fakeBandwidth = crdv1b1.Bandwidth{
		Rate:  "500k",
		Burst: "500k",
	}
	newFakeBandwidth = crdv1b1.Bandwidth{
		Rate:  "10M",
		Burst: "20M",
	}
)

type fakeLocalIPDetector struct {
	localIPs sets.Set[string]
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
			return "", memberlist.ErrNoNodeAvailable
		}
	}
	return c.node, nil
}

func (c *fakeSingleNodeCluster) AliveNodes() sets.Set[string] {
	return sets.New[string](c.node)
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
	mockController           *gomock.Controller
	mockOFClient             *openflowtest.MockClient
	mockRouteClient          *routetest.MockInterface
	crdClient                *fakeversioned.Clientset
	crdInformerFactory       crdinformers.SharedInformerFactory
	informerFactory          informers.SharedInformerFactory
	mockIPAssigner           *ipassignertest.MockIPAssigner
	mockServiceCIDRInterface *servicecidrtest.MockInterface
	podUpdateChannel         *channel.SubscribableChannel
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
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	externalIPPoolInformer := crdInformerFactory.Crd().V1beta1().ExternalIPPools()
	k8sClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	localIPDetector := &fakeLocalIPDetector{localIPs: sets.New[string](fakeLocalEgressIP1, fakeLocalEgressIP2)}

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, "ns1", "pod1", 1)
	addPodInterface(ifaceStore, "ns2", "pod2", 2)
	addPodInterface(ifaceStore, "ns3", "pod3", 3)
	addPodInterface(ifaceStore, "ns4", "pod4", 4)

	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	mockServiceCIDRProvider := servicecidrtest.NewMockInterface(controller)
	mockServiceCIDRProvider.EXPECT().AddEventHandler(gomock.Any())
	egressController, _ := NewEgressController(mockOFClient,
		k8sClient,
		&antreaClientGetter{clientset},
		crdClient,
		ifaceStore,
		mockRouteClient,
		fakeNode,
		"eth0",
		mockCluster,
		egressInformer,
		externalIPPoolInformer,
		nodeInformer,
		podUpdateChannel,
		mockServiceCIDRProvider,
		255,
		true,
		true,
	)
	egressController.localIPDetector = localIPDetector
	return &fakeController{
		EgressController:         egressController,
		mockController:           controller,
		mockOFClient:             mockOFClient,
		mockRouteClient:          mockRouteClient,
		crdClient:                crdClient,
		crdInformerFactory:       crdInformerFactory,
		informerFactory:          informerFactory,
		mockIPAssigner:           mockIPAssigner,
		mockServiceCIDRInterface: mockServiceCIDRProvider,
		podUpdateChannel:         podUpdateChannel,
	}
}

func TestSyncEgress(t *testing.T) {
	tests := []struct {
		name                   string
		supportSeparateSubnet  bool
		maxEgressIPsPerNode    int
		existingExternalIPPool *crdv1b1.ExternalIPPool
		existingEgress         *crdv1b1.Egress
		newExternalIPPool      *crdv1b1.ExternalIPPool
		newEgress              *crdv1b1.Egress
		existingEgressGroup    *cpv1b2.EgressGroup
		newEgressGroup         *cpv1b2.EgressGroup
		newLocalIPs            sets.Set[string]
		expectedEgresses       []*crdv1b1.Egress
		expectedCalls          func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner)
	}{
		{
			name: "Local IP becomes non local",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
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
			newLocalIPs: sets.New[string](),
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
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
				mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))

				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
			},
		},
		{
			name: "Non local IP becomes local",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
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
			newLocalIPs: sets.New[string](fakeRemoteEgressIP1),
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeRemoteEgressIP1, EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)

				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeRemoteEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
			},
		},
		{
			name: "Change from local Egress IP to another local one",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, Bandwidth: &fakeBandwidth},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, Bandwidth: &fakeBandwidth},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP2, EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)

				mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))
				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)

				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP2)
			},
		},
		{
			name: "Change from local Egress IP to a remote one",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
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
				mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))

				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeRemoteEgressIP1), uint32(0))
				mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1)
			},
		},
		{
			name: "Change from remote Egress IP to a local one",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
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

				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
			},
		},
		{
			name: "Add an Egress having overlapping Pods",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP2, EgressNode: fakeNode},
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
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
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
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP2, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP2, nil, true)
				// forceAdvertise depends on how fast the Egress status update is reflected in the informer cache, which doesn't really matter.
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP2, nil, gomock.Any())
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(3), net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(2))
			},
		},
		{
			name:                "Exceed maxEgressIPsPerNode",
			maxEgressIPsPerNode: 1,
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionFalse, Reason: "AssignmentError", Message: "Failed to assign the IP to EgressNode: no Node available"},
					}},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, nil, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
			},
		},
		{
			name:                "Remove Egress IP",
			maxEgressIPsPerNode: 1,
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeExternalIPPool},
				Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
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
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeExternalIPPool},
					Status:     crdv1b1.EgressStatus{},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, nil, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))

				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(2))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
			},
		},
		{
			name: "Update Egress from non-rate-limited to rate-limited",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).Times(3)

				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
			},
		},
		{
			name: "Update Egress from rate-limited to non-rate-limited",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).Times(3)

				mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))
			},
		},
		{
			name: "Update Egress rate-limited config",
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &fakeBandwidth},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &newFakeBandwidth},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, Bandwidth: &newFakeBandwidth},
					Status:     crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).Times(3)
				mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(10000), uint32(20000))
			},
		},
		{
			name:                  "Add SubnetInfo to ExternalIPPool",
			supportSeparateSubnet: true,
			existingExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges: []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
				},
			},
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			newExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges:   []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
					SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10},
				},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, nil, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))

				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, true)
				mockIPAssigner.EXPECT().GetInterfaceID(&crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}).Return(20, true)
				mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 20, net.ParseIP(fakeGatewayIP), 16)
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1))

				// forceAdvertise depends on how fast the Egress status update is reflected in the informer cache, which doesn't really matter.
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, gomock.Any())
			},
		},
		{
			name:                  "Update SubnetInfo of ExternalIPPool",
			supportSeparateSubnet: true,
			existingExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges:   []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
					SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10},
				},
			},
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			newExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges:   []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
					SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP2, PrefixLength: 16},
				},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().GetInterfaceID(&crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}).Return(20, true)
				mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 20, net.ParseIP(fakeGatewayIP), 16)
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1))

				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP2, PrefixLength: 16}, true)
				mockRouteClient.EXPECT().DeleteEgressRule(uint32(101), uint32(1))
				mockRouteClient.EXPECT().DeleteEgressRoutes(uint32(101))
				mockIPAssigner.EXPECT().GetInterfaceID(&crdv1b1.SubnetInfo{Gateway: fakeGatewayIP2, PrefixLength: 16}).Return(30, true)
				mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 30, net.ParseIP(fakeGatewayIP2), 16)
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1))

				// forceAdvertise depends on how fast the Egress status update is reflected in the informer cache, which doesn't really matter.
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP2, PrefixLength: 16}, gomock.Any())
			},
		},
		{
			name:                  "Add Egress having same SubnetInfo",
			supportSeparateSubnet: true,
			existingExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges:   []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
					SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10},
				},
			},
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			newEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP1, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
					Status: crdv1b1.EgressStatus{EgressIP: fakeLocalEgressIP2, EgressNode: fakeNode, Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					}},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().GetInterfaceID(&crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}).Return(20, true)
				mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 20, net.ParseIP(fakeGatewayIP), 16)
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1))

				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP2, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(2), net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP2), uint32(2))
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(2))

				// forceAdvertise depends on how fast the Egress status update is reflected in the informer cache, which doesn't really matter.
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP2, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, gomock.Any())
			},
		},
		{
			name:                  "Remove Egress IP with SubnetInfo ",
			supportSeparateSubnet: true,
			existingEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			},
			existingExternalIPPool: &crdv1b1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uid"},
				Spec: crdv1b1.ExternalIPPoolSpec{
					IPRanges:   []crdv1b1.IPRange{{Start: fakeLocalEgressIP1, End: fakeRemoteEgressIP1}},
					SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10},
				},
			},
			newEgress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeExternalIPPool},
			},
			existingEgressGroup: &cpv1b2.EgressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				GroupMembers: []cpv1b2.GroupMember{
					{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
				},
			},
			expectedEgresses: []*crdv1b1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec:       crdv1b1.EgressSpec{ExternalIPPool: fakeExternalIPPool},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockRouteClient *routetest.MockInterface, mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLocalEgressIP1, &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}, true)
				mockOFClient.EXPECT().InstallSNATMarkFlows(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockRouteClient.EXPECT().AddSNATRule(net.ParseIP(fakeLocalEgressIP1), uint32(1))
				mockIPAssigner.EXPECT().GetInterfaceID(&crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 10}).Return(20, true)
				mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 20, net.ParseIP(fakeGatewayIP), 16)
				mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1))

				mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
				mockRouteClient.EXPECT().DeleteEgressRule(uint32(101), uint32(1))
				mockRouteClient.EXPECT().DeleteEgressRoutes(uint32(101))
				mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
				mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initObjects := []runtime.Object{tt.existingEgress}
			if tt.existingExternalIPPool != nil {
				initObjects = append(initObjects, tt.existingExternalIPPool)
			}
			c := newFakeController(t, initObjects)
			c.supportSeparateSubnet = tt.supportSeparateSubnet
			c.trafficShapingEnabled = true
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
				c.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), tt.newEgress, metav1.UpdateOptions{})
			} else {
				c.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), tt.newEgress, metav1.CreateOptions{})
			}
			if tt.newExternalIPPool != nil {
				if tt.existingExternalIPPool != nil && tt.existingExternalIPPool.Name == tt.newExternalIPPool.Name {
					c.crdClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), tt.newExternalIPPool, metav1.UpdateOptions{})
				} else {
					c.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), tt.newExternalIPPool, metav1.CreateOptions{})
				}
			}

			if tt.newEgressGroup != nil {
				c.addEgressGroup(tt.newEgressGroup)
			}
			if tt.newLocalIPs != nil {
				c.localIPDetector = &fakeLocalIPDetector{localIPs: tt.newLocalIPs}
			}
			assert.NoError(t, wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
				if tt.newExternalIPPool != nil {
					pool, _ := c.externalIPPoolLister.Get(tt.newExternalIPPool.Name)
					if !reflect.DeepEqual(pool, tt.newExternalIPPool) {
						return false, nil
					}
				}
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
				gotEgress, err := c.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), expectedEgress.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.True(t, k8s.SemanticIgnoringTime.DeepEqual(expectedEgress, gotEgress))
			}
		})
	}
}

func TestPodUpdateShouldSyncEgress(t *testing.T) {
	egress := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pendingPod", Namespace: "ns1"}},
		},
	}
	c := newFakeController(t, []runtime.Object{egress})
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

func TestExternalIPPoolUpdateShouldSyncEgress(t *testing.T) {
	egress1 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
	}
	egress2 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
	}
	egress3 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: "another-pool"},
	}
	c := newFakeController(t, []runtime.Object{egress1, egress2, egress3})
	stopCh := make(chan struct{})
	defer close(stopCh)
	go c.podUpdateChannel.Run(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	assertItemsInQueue := func(items ...string) {
		require.NoError(t, wait.Poll(10*time.Millisecond, time.Second, func() (done bool, err error) {
			return c.queue.Len() == len(items), nil
		}))
		expectedItems := sets.New[string](items...)
		for i := 0; i < len(items); i++ {
			item, _ := c.queue.Get()
			c.queue.Done(item)
			expectedItems.Delete(item.(string))
		}
		assert.Empty(t, expectedItems)
	}

	assertItemsInQueue(egress1.Name, egress2.Name, egress3.Name)

	// Creating the pool with subnetInfo should trigger Egress sync.
	externalIPPool := &crdv1b1.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uidA"},
		Spec:       crdv1b1.ExternalIPPoolSpec{SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 2}},
	}
	c.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), externalIPPool, metav1.CreateOptions{})
	assertItemsInQueue(egress1.Name, egress2.Name)

	// Updating the pool's subnetInfo should trigger Egress sync.
	updateExternalIPPool := externalIPPool.DeepCopy()
	updateExternalIPPool.Spec.SubnetInfo.VLAN = 10
	c.crdClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), updateExternalIPPool, metav1.UpdateOptions{})
	assertItemsInQueue(egress1.Name, egress2.Name)

	// Updating the pool's annotation should not trigger Egress sync.
	updateExternalIPPool = updateExternalIPPool.DeepCopy()
	updateExternalIPPool.Annotations = map[string]string{"foo": "bar"}
	c.crdClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), updateExternalIPPool, metav1.UpdateOptions{})
	assertItemsInQueue()
}

func TestSyncOverlappingEgress(t *testing.T) {
	egress1 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup1 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
		},
	}
	// egress2 shares a Pod with egress1.
	egress2 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1},
	}
	egressGroup2 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
			{Pod: &cpv1b2.PodReference{Name: "pod3", Namespace: "ns3"}},
		},
	}
	// egress3 shares a Pod with egress1 and has the same EgressIP.
	egress3 := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressGroup3 := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod2", Namespace: "ns2"}},
			{Pod: &cpv1b2.PodReference{Name: "pod4", Namespace: "ns4"}},
		},
	}
	c := newFakeController(t, []runtime.Object{egress1, egress2, egress3})
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
	c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress1.Name, metav1.DeleteOptions{})
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
	c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress2.Name, metav1.DeleteOptions{})
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
	c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress3.Name, metav1.DeleteOptions{})
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
		egress               *crdv1b1.Egress
		egressIP             string
		scheduleErr          error
		updateErrorNum       int
		updateError          error
		getErrorNum          int
		selectedNodeForIP    string
		expectedUpdateCalled int
		expectedGetCalled    int
		expectedError        error
		expectedEgressStatus crdv1b1.EgressStatus
	}{
		{
			name: "updating static Egress succeeds immediately",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			egressIP:             fakeLocalEgressIP1,
			expectedUpdateCalled: 1,
			expectedEgressStatus: crdv1b1.EgressStatus{
				EgressNode: fakeNode,
				EgressIP:   fakeLocalEgressIP1,
			},
		},
		{
			name: "updating static Egress succeeds after one update conflict failure",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			egressIP:             fakeLocalEgressIP1,
			updateErrorNum:       1,
			updateError:          updateConflictError,
			expectedUpdateCalled: 2,
			expectedGetCalled:    1,
			expectedEgressStatus: crdv1b1.EgressStatus{
				EgressNode: fakeNode,
				EgressIP:   fakeLocalEgressIP1,
			},
		},
		{
			name: "updating static Egress fails after one update failure",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			egressIP:             fakeLocalEgressIP1,
			updateErrorNum:       1,
			updateError:          updateError,
			expectedUpdateCalled: 1,
			expectedError:        updateError,
		},
		{
			name: "updating static Egress fails after one update conflict failure and one get failure",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
			},
			egressIP:             fakeLocalEgressIP1,
			updateErrorNum:       1,
			updateError:          updateConflictError,
			getErrorNum:          1,
			expectedUpdateCalled: 1,
			expectedGetCalled:    1,
			expectedError:        getError,
		},
		{
			name: "updating static Egress with remote IP does nothing",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1},
			},
			egressIP: fakeRemoteEgressIP1,
		},
		{
			name: "updating HA Egress with local IP succeeds immediately",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
				Status: crdv1b1.EgressStatus{
					Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			egressIP:             fakeLocalEgressIP1,
			expectedUpdateCalled: 1,
			expectedEgressStatus: crdv1b1.EgressStatus{
				EgressNode: fakeNode,
				EgressIP:   fakeLocalEgressIP1,
				Conditions: []crdv1b1.EgressCondition{
					{Type: crdv1b1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "updating HA Egress with remote IP does nothing",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
				Status: crdv1b1.EgressStatus{
					Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			egressIP: fakeRemoteEgressIP1,
			expectedEgressStatus: crdv1b1.EgressStatus{
				Conditions: []crdv1b1.EgressCondition{
					{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "updating HA Egress with schedule error succeeds immediately",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
				Status: crdv1b1.EgressStatus{
					Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			scheduleErr:          memberlist.ErrNoNodeAvailable,
			selectedNodeForIP:    fakeNode,
			expectedUpdateCalled: 1,
			expectedEgressStatus: crdv1b1.EgressStatus{
				Conditions: []crdv1b1.EgressCondition{
					{Type: crdv1b1.IPAssigned, Status: v1.ConditionFalse, Reason: "AssignmentError", Message: "Failed to assign the IP to EgressNode: no Node available"},
					{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "updating HA Egress with schedule error succeeds after one update conflict failure",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
				Status: crdv1b1.EgressStatus{
					Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			scheduleErr:          memberlist.ErrNoNodeAvailable,
			selectedNodeForIP:    fakeNode,
			updateError:          updateConflictError,
			updateErrorNum:       2,
			expectedUpdateCalled: 3,
			expectedGetCalled:    2,
			expectedEgressStatus: crdv1b1.EgressStatus{
				Conditions: []crdv1b1.EgressCondition{
					{Type: crdv1b1.IPAssigned, Status: v1.ConditionFalse, Reason: "AssignmentError", Message: "Failed to assign the IP to EgressNode: no Node available"},
					{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "updating HA Egress with schedule error does nothing when the Node is not selected to update",
			egress: &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", ResourceVersion: "fake-ResourceVersion"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
				Status: crdv1b1.EgressStatus{
					Conditions: []crdv1b1.EgressCondition{
						{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			scheduleErr:       memberlist.ErrNoNodeAvailable,
			selectedNodeForIP: fakeNode2, // Not this Node.
			expectedEgressStatus: crdv1b1.EgressStatus{
				Conditions: []crdv1b1.EgressCondition{
					{Type: crdv1b1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fakeversioned.NewSimpleClientset(tt.egress)
			getCalled := 0
			fakeClient.PrependReactor("get", "egresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
				getCalled += 1
				if getCalled <= tt.getErrorNum {
					return true, nil, getError
				}
				return false, nil, nil
			})
			updateCalled := 0
			fakeClient.PrependReactor("update", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateCalled += 1
				if updateCalled <= tt.updateErrorNum {
					return true, nil, tt.updateError
				}
				return false, nil, nil
			})

			localIPDetector := &fakeLocalIPDetector{localIPs: sets.New[string](fakeLocalEgressIP1)}
			cluster := newFakeMemberlistCluster([]string{tt.selectedNodeForIP})
			c := &EgressController{crdClient: fakeClient, nodeName: fakeNode, localIPDetector: localIPDetector, cluster: cluster}
			err := c.updateEgressStatus(tt.egress, tt.egressIP, tt.scheduleErr)
			if err != tt.expectedError {
				t.Errorf("Update Egress error not match, got: %v, expected: %v", err, tt.expectedError)
			}
			assert.Equal(t, tt.expectedGetCalled, getCalled, "Get called num not match")
			assert.Equal(t, tt.expectedUpdateCalled, updateCalled, "Update called num not match")
			gotEgress, _ := c.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), tt.egress.Name, metav1.GetOptions{})
			assert.True(t, k8s.SemanticIgnoringTime.DeepEqual(tt.expectedEgressStatus, gotEgress.Status), "Expected:\n%v\nGot:\n%v", tt.expectedEgressStatus, gotEgress.Status)
		})
	}
}

func TestGetEgress(t *testing.T) {
	egress := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
		Status: crdv1b1.EgressStatus{
			EgressNode: fakeNode,
			EgressIP:   fakeLocalEgressIP1,
		},
	}
	egressGroup := &cpv1b2.EgressGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		GroupMembers: []cpv1b2.GroupMember{
			{Pod: &cpv1b2.PodReference{Name: "pod1", Namespace: "ns1"}},
		},
	}

	c := newFakeController(t, []runtime.Object{egress})
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
		expectedEgressIP   string
		expectedEgressNode string
		expectedErr        string
	}{
		{
			name: "local egress applied on a pod",
			args: args{
				ns:      "ns1",
				podName: "pod1",
			},
			expectedEgressName: "egressA",
			expectedEgressIP:   fakeLocalEgressIP1,
			expectedEgressNode: fakeNode,
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
			gotEgressName, gotEgressIP, gotEgressNode, err := c.GetEgress(tt.args.ns, tt.args.podName)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedEgressName, gotEgressName)
			assert.Equal(t, tt.expectedEgressIP, gotEgressIP)
			assert.Equal(t, tt.expectedEgressNode, gotEgressNode)
		})
	}
}

func TestGetEgressIPByMark(t *testing.T) {
	egress := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}

	c := newFakeController(t, []runtime.Object{egress})
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

func TestUpdateServiceCIDRs(t *testing.T) {
	c := newFakeController(t, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	// Retry immediately.
	c.serviceCIDRUpdateRetryDelay = 0

	serviceCIDRs := []*net.IPNet{
		ip.MustParseCIDR("10.96.0.0/16"),
		ip.MustParseCIDR("1096::/64"),
	}
	assert.Len(t, c.serviceCIDRUpdateCh, 0)
	// Call the handler the 1st time, it should enqueue an event.
	c.onServiceCIDRUpdate(serviceCIDRs)
	assert.Len(t, c.serviceCIDRUpdateCh, 1)
	// Call the handler the 2nd time, it should not block and should discard the event.
	c.onServiceCIDRUpdate(serviceCIDRs)
	assert.Len(t, c.serviceCIDRUpdateCh, 1)

	// In the 1st round, returning the ServiceCIDRs fails, it should not retry.
	c.mockServiceCIDRInterface.EXPECT().GetServiceCIDRs().Return(nil, fmt.Errorf("not initialized"))

	go c.updateServiceCIDRs(stopCh)

	// Wait for the event to be processed.
	require.Eventually(t, func() bool {
		return len(c.serviceCIDRUpdateCh) == 0
	}, time.Second, 100*time.Millisecond)
	// In the 2nd round, returning the ServiceCIDR succeeds but installing flows fails, it should retry.
	c.mockServiceCIDRInterface.EXPECT().GetServiceCIDRs().Return(serviceCIDRs, nil)
	c.mockOFClient.EXPECT().InstallSNATBypassServiceFlows(serviceCIDRs).Return(fmt.Errorf("transient error"))
	// In the 3rd round, both succeed.
	finishCh := make(chan struct{})
	c.mockServiceCIDRInterface.EXPECT().GetServiceCIDRs().Return(serviceCIDRs, nil)
	c.mockOFClient.EXPECT().InstallSNATBypassServiceFlows(serviceCIDRs).Do(func(_ []*net.IPNet) { close(finishCh) }).Return(nil)
	// Enqueue only one event as the 2nd failure is supposed to trigger a retry.
	c.onServiceCIDRUpdate(serviceCIDRs)

	select {
	case <-finishCh:
	case <-time.After(time.Second):
		t.Errorf("InstallSNATBypassServiceFlows didn't succeed in time")
	}
}

func checkQueueItemExistence(t *testing.T, queue workqueue.RateLimitingInterface, items ...string) {
	t.Logf("queue len %d", queue.Len())
	require.Eventually(t, func() bool {
		return len(items) == queue.Len()
	}, time.Second, 10*time.Millisecond, "Didn't find enough items in the queue")
	expectedItems := sets.New[string](items...)
	actualItems := sets.New[string]()
	for i := 0; i < len(expectedItems); i++ {
		key, _ := queue.Get()
		actualItems.Insert(key.(string))
		queue.Done(key)
	}
	assert.Equal(t, expectedItems, actualItems)
}

func TestCompareEgressStatus(t *testing.T) {
	newCondition := func(t crdv1b1.EgressConditionType, c v1.ConditionStatus, reason string, message string) crdv1b1.EgressCondition {
		return crdv1b1.EgressCondition{
			Type:    t,
			Status:  c,
			Message: message,
			Reason:  reason,
		}
	}
	tests := []struct {
		name           string
		status1        *crdv1b1.EgressStatus
		status2        *crdv1b1.EgressStatus
		expectedReturn bool // true if equal, false if not
	}{
		{
			name: "Different EgressIP",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.2",
				EgressNode: "node1",
			},
			expectedReturn: false,
		},
		{
			name: "Different EgressNode",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node2",
			},
			expectedReturn: false,
		},
		{
			name: "Egresses are the same",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAssigned, v1.ConditionTrue, "Assigned", "EgressIP is successfully assigned to EgressNode"),
				},
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAssigned, v1.ConditionTrue, "Assigned", "EgressIP is successfully assigned to EgressNode"),
				},
			},
			expectedReturn: true,
		},
		{
			name: "EgressStatus Condition is different",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAssigned, v1.ConditionTrue, "Assigned", "EgressIP is successfully assigned to EgressNode"),
				},
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAssigned, v1.ConditionFalse, "NoAvailableNode", "No available Node can be elected as EgressNode"),
				},
			},
			expectedReturn: false,
		},
		{
			name: "New Status has relevant Condition that old one doesn't",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{},
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAssigned, v1.ConditionTrue, "Assigned", "EgressIP is successfully assigned to EgressNode"),
				},
			},
			expectedReturn: false,
		},
		{
			name: "New Status has irrelevant Condition that old one doesn't",
			status1: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{},
			},
			status2: &crdv1b1.EgressStatus{
				EgressIP:   "1.1.1.1",
				EgressNode: "node1",
				Conditions: []crdv1b1.EgressCondition{
					newCondition(crdv1b1.IPAllocated, v1.ConditionTrue, "Allocated", "EgressIP is successfully allocated"),
				},
			},
			expectedReturn: true,
		},
		{
			name:           "nils are the same",
			expectedReturn: true,
		},
		{
			name: "nil and non empty one are different",
			status2: &crdv1b1.EgressStatus{
				EgressIP: "1.1.1.1",
			},
			expectedReturn: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareEgressStatus(tt.status1, tt.status2)
			assert.Equal(t, tt.expectedReturn, result)
		})
	}
}

func TestEgressControllerReplaceEgressIPs(t *testing.T) {
	c := newFakeController(t, []runtime.Object{
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
			Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1, ExternalIPPool: fakeExternalIPPool},
			Status:     crdv1b1.EgressStatus{EgressNode: fakeNode, EgressIP: fakeLocalEgressIP1},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
			Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP2, ExternalIPPool: fakeExternalIPPool},
			Status:     crdv1b1.EgressStatus{EgressNode: fakeNode, EgressIP: fakeLocalEgressIP2},
		},
		// Should not be included.
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidA"},
			Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1, ExternalIPPool: fakeExternalIPPool},
			Status:     crdv1b1.EgressStatus{EgressNode: fakeNode2, EgressIP: fakeRemoteEgressIP1},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressD", UID: "uidA"},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.2.3.4", ExternalIPPool: "other-pool"},
			Status:     crdv1b1.EgressStatus{EgressNode: fakeNode, EgressIP: "1.2.3.4"},
		},
		&crdv1b1.ExternalIPPool{
			ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool, UID: "pool-uidA"},
			Spec:       crdv1b1.ExternalIPPoolSpec{SubnetInfo: &crdv1b1.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 2}},
		},
		&crdv1b1.ExternalIPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "other-pool", UID: "pool-uidB"},
			Spec:       crdv1b1.ExternalIPPoolSpec{},
		},
	})
	stopCh := make(chan struct{})
	defer close(stopCh)
	go c.podUpdateChannel.Run(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	c.mockIPAssigner.EXPECT().InitIPs(map[string]*crdv1b1.SubnetInfo{
		fakeLocalEgressIP1: {Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 2},
		fakeLocalEgressIP2: {Gateway: fakeGatewayIP, PrefixLength: 16, VLAN: 2},
		"1.2.3.4":          nil,
	})
	c.replaceEgressIPs()
}
