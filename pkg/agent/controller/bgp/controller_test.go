// Copyright 2024 Antrea Authors
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

package bgp

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/bgp"
	bgptest "antrea.io/antrea/pkg/agent/bgp/testing"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	namespaceDefault    = "default"
	namespaceKubeSystem = "kube-system"
)

var (
	podIPv4CIDR      = ip.MustParseCIDR("10.10.0.0/24")
	podIPv4CIDRRoute = bgp.Route{Prefix: podIPv4CIDR.String()}
	podIPv6CIDR      = ip.MustParseCIDR("fec0:10:10::/64")
	podIPv6CIDRRoute = bgp.Route{Prefix: podIPv6CIDR.String()}
	nodeIPv4Addr     = ip.MustParseCIDR("192.168.77.100/24")

	testNodeConfig = &config.NodeConfig{
		PodIPv4CIDR:  podIPv4CIDR,
		PodIPv6CIDR:  podIPv6CIDR,
		NodeIPv4Addr: nodeIPv4Addr,
		Name:         localNodeName,
	}

	peer1ASN          = int32(65531)
	peer1AuthPassword = "bgp-peer1" // #nosec G101
	ipv4Peer1Addr     = "192.168.77.251"
	ipv6Peer1Addr     = "fec0::196:168:77:251"
	ipv4Peer1         = generateBGPPeer(ipv4Peer1Addr, peer1ASN, 179, 120)
	ipv6Peer1         = generateBGPPeer(ipv6Peer1Addr, peer1ASN, 179, 120)
	ipv4Peer1Config   = generateBGPPeerConfig(&ipv4Peer1, peer1AuthPassword)
	ipv6Peer1Config   = generateBGPPeerConfig(&ipv6Peer1, peer1AuthPassword)
	ipv4Peer1Status   = bgp.PeerStatus{
		Address:      ipv4Peer1Addr,
		ASN:          peer1ASN,
		SessionState: bgp.SessionActive,
	}
	ipv6Peer1Status = bgp.PeerStatus{
		Address:      ipv6Peer1Addr,
		ASN:          peer1ASN,
		SessionState: bgp.SessionActive,
	}

	peer2ASN          = int32(65532)
	peer2AuthPassword = "bgp-peer2" // #nosec G101
	ipv4Peer2Addr     = "192.168.77.252"
	ipv6Peer2Addr     = "fec0::196:168:77:252"
	ipv4Peer2         = generateBGPPeer(ipv4Peer2Addr, peer2ASN, 179, 120)
	ipv6Peer2         = generateBGPPeer(ipv6Peer2Addr, peer2ASN, 179, 120)
	ipv4Peer2Config   = generateBGPPeerConfig(&ipv4Peer2, peer2AuthPassword)
	ipv6Peer2Config   = generateBGPPeerConfig(&ipv6Peer2, peer2AuthPassword)
	ipv4Peer2Status   = bgp.PeerStatus{
		Address:      ipv4Peer2Addr,
		ASN:          peer2ASN,
		SessionState: bgp.SessionActive,
	}
	ipv6Peer2Status = bgp.PeerStatus{
		Address:      ipv6Peer2Addr,
		ASN:          peer2ASN,
		SessionState: bgp.SessionActive,
	}

	updatedIPv4Peer2       = generateBGPPeer(ipv4Peer2Addr, peer2ASN, 179, 60)
	updatedIPv6Peer2       = generateBGPPeer(ipv6Peer2Addr, peer2ASN, 179, 60)
	updatedIPv4Peer2Config = generateBGPPeerConfig(&updatedIPv4Peer2, peer2AuthPassword)
	updatedIPv6Peer2Config = generateBGPPeerConfig(&updatedIPv6Peer2, peer2AuthPassword)

	peer3ASN          = int32(65533)
	peer3AuthPassword = "bgp-peer3" // #nosec G101
	ipv4Peer3Addr     = "192.168.77.253"
	ipv6Peer3Addr     = "fec0::196:168:77:253"
	ipv4Peer3         = generateBGPPeer(ipv4Peer3Addr, peer3ASN, 179, 120)
	ipv6Peer3         = generateBGPPeer(ipv6Peer3Addr, peer3ASN, 179, 120)
	ipv4Peer3Config   = generateBGPPeerConfig(&ipv4Peer3, peer3AuthPassword)
	ipv6Peer3Config   = generateBGPPeerConfig(&ipv6Peer3, peer3AuthPassword)

	nodeLabels1      = map[string]string{"node": "control-plane"}
	nodeLabels2      = map[string]string{"os": "linux"}
	nodeLabels3      = map[string]string{"node": "control-plane", "os": "linux"}
	nodeAnnotations1 = map[string]string{types.NodeBGPRouterIDAnnotationKey: "192.168.77.100"}
	nodeAnnotations2 = map[string]string{types.NodeBGPRouterIDAnnotationKey: "10.10.0.100"}

	localNodeName = "local"
	node          = generateNode(localNodeName, nodeLabels1, nodeAnnotations1)

	ipv4EgressIP1      = "192.168.77.200"
	ipv4EgressIP1Route = bgp.Route{Prefix: ipStrToPrefix(ipv4EgressIP1)}
	ipv6EgressIP1      = "fec0::192:168:77:200"
	ipv6EgressIP1Route = bgp.Route{Prefix: ipStrToPrefix(ipv6EgressIP1)}
	ipv4EgressIP2      = "192.168.77.201"
	ipv6EgressIP2      = "fec0::192:168:77:2001"

	ipv4Egress1 = generateEgress("eg1-4", ipv4EgressIP1, localNodeName)
	ipv6Egress1 = generateEgress("eg1-6", ipv6EgressIP1, localNodeName)
	ipv4Egress2 = generateEgress("eg2-4", ipv4EgressIP2, "test-remote-node")
	ipv6Egress2 = generateEgress("eg2-6", ipv6EgressIP2, "test-remote-node")

	bgpPolicyName1 = "policy-1"
	bgpPolicyName2 = "policy-2"
	bgpPolicyName3 = "policy-3"
	bgpPolicyName4 = "policy-4"

	creationTimestamp      = metav1.Now()
	creationTimestampAdd1s = metav1.NewTime(creationTimestamp.Add(time.Second))
	creationTimestampAdd2s = metav1.NewTime(creationTimestamp.Add(2 * time.Second))
	creationTimestampAdd3s = metav1.NewTime(creationTimestamp.Add(3 * time.Second))

	clusterIPv4s     = []string{"10.96.10.10", "10.96.10.11"}
	externalIPv4s    = []string{"192.168.77.100", "192.168.77.101"}
	loadBalancerIPv4 = "192.168.77.150"
	endpointIPv4     = "10.10.0.10"
	clusterIPv6s     = []string{"fec0::10:96:10:10", "fec0::10:96:10:11"}
	externalIPv6s    = []string{"fec0::192:168:77:100", "fec0::192:168:77:101"}
	loadBalancerIPv6 = "fec0::192:168:77:150"
	endpointIPv6     = "fec0::10:10:0:10"

	ipv4ClusterIPName1   = "clusterip-4"
	ipv4ClusterIPName2   = "clusterip-4-local"
	ipv6ClusterIPName1   = "clusterip-6"
	ipv6ClusterIPName2   = "clusterip-6-local"
	ipv4LoadBalancerName = "loadbalancer-4"
	ipv6LoadBalancerName = "loadbalancer-6"

	clusterIPv4Route1     = bgp.Route{Prefix: ipStrToPrefix(clusterIPv4s[0])}
	clusterIPv6Route1     = bgp.Route{Prefix: ipStrToPrefix(clusterIPv6s[0])}
	clusterIPv4Route2     = bgp.Route{Prefix: ipStrToPrefix(clusterIPv4s[1])}
	clusterIPv6Route2     = bgp.Route{Prefix: ipStrToPrefix(clusterIPv6s[1])}
	externalIPv4Route1    = bgp.Route{Prefix: ipStrToPrefix(externalIPv4s[0])}
	externalIPv6Route1    = bgp.Route{Prefix: ipStrToPrefix(externalIPv6s[0])}
	externalIPv4Route2    = bgp.Route{Prefix: ipStrToPrefix(externalIPv4s[1])}
	externalIPv6Route2    = bgp.Route{Prefix: ipStrToPrefix(externalIPv6s[1])}
	loadBalancerIPv4Route = bgp.Route{Prefix: ipStrToPrefix(loadBalancerIPv4)}
	loadBalancerIPv6Route = bgp.Route{Prefix: ipStrToPrefix(loadBalancerIPv6)}

	allRoutes = map[bgp.Route]RouteMetadata{
		clusterIPv4Route1:     {Type: ServiceClusterIP, K8sObjRef: getServiceName(ipv4ClusterIPName1)},
		clusterIPv6Route1:     {Type: ServiceClusterIP, K8sObjRef: getServiceName(ipv6ClusterIPName1)},
		clusterIPv4Route2:     {Type: ServiceClusterIP, K8sObjRef: getServiceName(ipv4LoadBalancerName)},
		clusterIPv6Route2:     {Type: ServiceClusterIP, K8sObjRef: getServiceName(ipv6LoadBalancerName)},
		externalIPv4Route1:    {Type: ServiceExternalIP, K8sObjRef: getServiceName(ipv4ClusterIPName1)},
		externalIPv6Route1:    {Type: ServiceExternalIP, K8sObjRef: getServiceName(ipv6ClusterIPName1)},
		externalIPv4Route2:    {Type: ServiceExternalIP, K8sObjRef: getServiceName(ipv4LoadBalancerName)},
		externalIPv6Route2:    {Type: ServiceExternalIP, K8sObjRef: getServiceName(ipv6LoadBalancerName)},
		loadBalancerIPv4Route: {Type: ServiceLoadBalancerIP, K8sObjRef: getServiceName(ipv4LoadBalancerName)},
		loadBalancerIPv6Route: {Type: ServiceLoadBalancerIP, K8sObjRef: getServiceName(ipv6LoadBalancerName)},
		ipv4EgressIP1Route:    {Type: EgressIP, K8sObjRef: "eg1-4"},
		ipv6EgressIP1Route:    {Type: EgressIP, K8sObjRef: "eg1-6"},
		podIPv4CIDRRoute:      {Type: NodeIPAMPodCIDR},
		podIPv6CIDRRoute:      {Type: NodeIPAMPodCIDR},
	}

	endpointSliceSuffix = rand.String(5)
	ipv4ClusterIP1      = generateService(ipv4ClusterIPName1, corev1.ServiceTypeClusterIP, clusterIPv4s[0], externalIPv4s[0], "", false, false)
	ipv4ClusterIP1Eps   = generateEndpointSlice(ipv4ClusterIPName1, endpointSliceSuffix, false, false, endpointIPv4)
	ipv4ClusterIP2      = generateService(ipv4ClusterIPName2, corev1.ServiceTypeClusterIP, clusterIPv4s[0], externalIPv4s[0], "", true, true)
	ipv4ClusterIP2Eps   = generateEndpointSlice(ipv4ClusterIPName2, endpointSliceSuffix, false, false, endpointIPv4)

	ipv6ClusterIP1    = generateService(ipv6ClusterIPName1, corev1.ServiceTypeClusterIP, clusterIPv6s[0], externalIPv6s[0], "", false, false)
	ipv6ClusterIP1Eps = generateEndpointSlice(ipv6ClusterIPName1, endpointSliceSuffix, false, false, endpointIPv6)
	ipv6ClusterIP2    = generateService(ipv6ClusterIPName2, corev1.ServiceTypeClusterIP, clusterIPv6s[0], externalIPv6s[0], "", true, true)
	ipv6ClusterIP2Eps = generateEndpointSlice(ipv6ClusterIPName2, endpointSliceSuffix, false, false, endpointIPv6)

	ipv4LoadBalancer    = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, clusterIPv4s[1], externalIPv4s[1], loadBalancerIPv4, false, false)
	ipv4LoadBalancerEps = generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, false, false, endpointIPv4)
	ipv6LoadBalancer    = generateService(ipv6LoadBalancerName, corev1.ServiceTypeLoadBalancer, clusterIPv6s[1], externalIPv6s[1], loadBalancerIPv6, false, false)
	ipv6LoadBalancerEps = generateEndpointSlice(ipv6LoadBalancerName, endpointSliceSuffix, false, false, endpointIPv6)

	bgpPeerPasswords = map[string]string{
		generateBGPPeerKey(ipv4Peer1Addr, peer1ASN): peer1AuthPassword,
		generateBGPPeerKey(ipv6Peer1Addr, peer1ASN): peer1AuthPassword,
		generateBGPPeerKey(ipv4Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv6Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv4Peer3Addr, peer3ASN): peer3AuthPassword,
		generateBGPPeerKey(ipv6Peer3Addr, peer3ASN): peer3AuthPassword,
	}
)

type fakeController struct {
	*Controller
	mockController     *gomock.Controller
	mockBGPServer      *bgptest.MockInterface
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	client             *fake.Clientset
	informerFactory    informers.SharedInformerFactory
}

func (c *fakeController) startInformers(stopCh chan struct{}) {
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
}

func newFakeController(t *testing.T, objects []runtime.Object, crdObjects []runtime.Object, ipv4Enabled, ipv6Enabled bool) *fakeController {
	ctrl := gomock.NewController(t)
	mockBGPServer := bgptest.NewMockInterface(ctrl)

	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	informerFactory := informers.NewSharedInformerFactory(client, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()
	serviceInformer := informerFactory.Core().V1().Services()
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	endpointSliceInformer := informerFactory.Discovery().V1().EndpointSlices()
	bgpPolicyInformer := crdInformerFactory.Crd().V1alpha1().BGPPolicies()

	bgpController, _ := NewBGPPolicyController(nodeInformer,
		serviceInformer,
		egressInformer,
		bgpPolicyInformer,
		endpointSliceInformer,
		true,
		client,
		testNodeConfig,
		&config.NetworkConfig{
			IPv4Enabled: ipv4Enabled,
			IPv6Enabled: ipv6Enabled,
		})
	bgpController.egressEnabled = true
	bgpController.newBGPServerFn = func(_ *bgp.GlobalConfig) bgp.Interface {
		return mockBGPServer
	}

	return &fakeController{
		Controller:         bgpController,
		mockController:     ctrl,
		mockBGPServer:      mockBGPServer,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		client:             client,
		informerFactory:    informerFactory,
	}
}

func TestBGPPolicyAdd(t *testing.T) {
	testCases := []struct {
		name          string
		ipv4Enabled   bool
		ipv6Enabled   bool
		policiesToAdd []runtime.Object
		objects       []runtime.Object
		crdObjects    []runtime.Object
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectedError string
	}{
		{
			name:        "IPv4, as effective BGPPolicy, advertise ClusterIP",
			ipv4Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1},
				nil),
			},
			objects: []runtime.Object{
				ipv4ClusterIP1,
				ipv4ClusterIP1Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{clusterIPv4Route1},
				[]bgp.PeerConfig{ipv4Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route1})
			},
		},
		{
			name:        "IPv4, as effective BGPPolicy configured with confederation, advertise ClusterIP",
			ipv4Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1},
				&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			},
			objects: []runtime.Object{
				ipv4ClusterIP1,
				ipv4ClusterIP1Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{clusterIPv4Route1},
				[]bgp.PeerConfig{ipv4Peer1Config},
				&confederationConfig{100, sets.New[uint32](uint32(65001))}),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route1})
			},
		},
		{
			name:        "IPv6, as effective BGPPolicy, advertise ExternalIP",
			ipv6Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				false,
				true,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv6Peer1},
				nil)},
			objects: []runtime.Object{
				ipv6ClusterIP1,
				ipv6ClusterIP1Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{externalIPv6Route1},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv6Route1})
			},
		},
		{
			name:        "IPv4 & IPv6, as effective BGPPolicy, advertise LoadBalancerIP",
			ipv4Enabled: true,
			ipv6Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				false,
				false,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1},
				nil)},
			objects: []runtime.Object{
				ipv4LoadBalancer,
				ipv4LoadBalancerEps,
				ipv6LoadBalancer,
				ipv6LoadBalancerEps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{loadBalancerIPv4Route, loadBalancerIPv6Route},
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
			},
		},
		{
			name:        "IPv4, as effective BGPPolicy, advertise EgressIP",
			ipv4Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				true,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1},
				nil)},
			objects: []runtime.Object{node},
			crdObjects: []runtime.Object{
				ipv4Egress1,
				ipv4Egress2,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{ipv4EgressIP1Route},
				[]bgp.PeerConfig{ipv4Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{ipv4EgressIP1Route})
			},
		},
		{
			name:        "IPv6, as effective BGPPolicy, advertise Pod CIDR",
			ipv6Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				true,
				true,
				true,
				true,
				[]v1alpha1.BGPPeer{ipv6Peer1},
				nil)},
			objects: []runtime.Object{node},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name:        "IPv4 & IPv6, as effective BGPPolicy, not advertise any Service IP due to no local Endpoint",
			ipv4Enabled: true,
			ipv6Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				1179,
				65001,
				true,
				true,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1},
				nil)},
			objects: []runtime.Object{
				ipv4ClusterIP2,
				ipv4ClusterIP2Eps,
				ipv6ClusterIP2,
				ipv6ClusterIP2Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				1179,
				65001,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				nil,
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
			},
		},
		{
			name:        "IPv4, as alternative BGPPolicy",
			ipv4Enabled: true,
			policiesToAdd: []runtime.Object{generateBGPPolicy(bgpPolicyName2,
				creationTimestamp, // As the effective BGPPolicy because the creationTimestamp is the oldest.
				nodeLabels1,
				179,
				65000,
				true,
				false,
				false,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1},
				nil),
				generateBGPPolicy(bgpPolicyName1,
					creationTimestampAdd1s,
					nodeLabels1,
					179,
					65000,
					true,
					false,
					false,
					false,
					false,
					[]v1alpha1.BGPPeer{ipv4Peer1},
					nil)},
			objects: []runtime.Object{ipv4ClusterIP1, ipv4ClusterIP1Eps, node},
			existingState: generateBGPPolicyState(bgpPolicyName2,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{clusterIPv4Route1},
				[]bgp.PeerConfig{ipv4Peer1Config},
				nil),
			expectedState: generateBGPPolicyState(bgpPolicyName2,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{clusterIPv4Route1},
				[]bgp.PeerConfig{ipv4Peer1Config},
				nil),
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, tt.objects, append(tt.crdObjects, tt.policiesToAdd...), tt.ipv4Enabled, tt.ipv6Enabled)

			stopCh := make(chan struct{})
			defer close(stopCh)
			ctx := context.Background()
			c.startInformers(stopCh)

			// Fake the BGPPolicy state and the passwords of BGP peers.
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			c.bgpPeerPasswords = bgpPeerPasswords

			// Wait for the dummy event triggered by BGPPolicy add events.
			waitAndGetDummyEvent(t, c)
			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			if tt.expectedError != "" {
				assert.EqualError(t, c.syncBGPPolicy(ctx), tt.expectedError)
			} else {
				assert.NoError(t, c.syncBGPPolicy(ctx))
			}
			// Done with the dummy event.
			doneDummyEvent(t, c)
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestBGPPolicyUpdate(t *testing.T) {
	effectivePolicy := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		},
		&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}})
	effectivePolicyState := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{clusterIPv4Route2, clusterIPv6Route2, loadBalancerIPv4Route, loadBalancerIPv6Route, podIPv4CIDRRoute, podIPv6CIDRRoute},
		[]bgp.PeerConfig{ipv4Peer1Config,
			ipv6Peer1Config,
			ipv4Peer2Config,
			ipv6Peer2Config,
		},
		&confederationConfig{100, sets.New[uint32](uint32(65001))})
	alternativePolicy := generateBGPPolicy(bgpPolicyName2,
		creationTimestampAdd1s,
		nodeLabels1,
		1179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		},
		&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}})
	unrelatedPolicy := generateBGPPolicy(bgpPolicyName3,
		creationTimestampAdd2s,
		nodeLabels2,
		179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		},
		&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}})
	objects := []runtime.Object{
		ipv4ClusterIP2,
		ipv4ClusterIP2Eps,
		ipv6ClusterIP2,
		ipv6ClusterIP2Eps,
		ipv4LoadBalancer,
		ipv4LoadBalancerEps,
		ipv6LoadBalancer,
		ipv6LoadBalancerEps,
		node,
	}
	crdObjects := []runtime.Object{ipv4Egress1,
		ipv4Egress2,
		ipv6Egress1,
		ipv6Egress2,
		effectivePolicy,
		alternativePolicy,
		unrelatedPolicy,
	}
	testCases := []struct {
		name           string
		policyToUpdate *v1alpha1.BGPPolicy
		existingState  *bgpPolicyState
		expectedState  *bgpPolicyState
		expectedCalls  func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectedError  string
	}{
		{
			name: "Effective BGPPolicy, update NodeSelector (not applied to current Node), an alternative takes effect",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels2,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				},
				&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
			expectedState: generateBGPPolicyState(bgpPolicyName2,
				1179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65001))},
			),
		},
		{
			name: "Effective BGPPolicy, update NodeSelector (not applied to current Node), failed to stop current BGP server",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels2,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any()).Return(fmt.Errorf("failed to stop"))
			},
			expectedState: deepCopyBGPPolicyState(effectivePolicyState),
			expectedError: "failed to stop current BGP server: failed to stop",
		},
		{
			name: "Effective BGPPolicy, update Advertisements",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				false,
				true,
				false,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					externalIPv4Route2,
					externalIPv6Route2,
					ipv4EgressIP1Route,
					ipv6EgressIP1Route,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65001))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{ipv4EgressIP1Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{ipv6EgressIP1Route})

				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name: "Effective BGPPolicy, update LocalASN and Advertisements",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65001,
				false,
				true,
				false,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65001,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					externalIPv4Route2,
					externalIPv6Route2,
					ipv4EgressIP1Route,
					ipv6EgressIP1Route,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65001))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{ipv4EgressIP1Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{ipv6EgressIP1Route})
			},
		},
		{
			name: "Effective BGPPolicy, update ListenPort",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				1179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				1179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65001))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name: "Effective BGPPolicy, update confederation peers",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				1179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 101, MemberASNs: []int32{65001}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				1179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{101, sets.New[uint32](uint32(65001))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name: "Effective BGPPolicy, update confederation identifier",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65002}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65002))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name: "Effective BGPPolicy, remove confederation",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				},
				nil),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv6Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name: "Effective BGPPolicy, update BGPPeers",
			policyToUpdate: generateBGPPolicy(bgpPolicyName1,
				creationTimestamp,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{updatedIPv4Peer2,
					updatedIPv6Peer2,
					ipv4Peer3,
					ipv6Peer3},
				&v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					clusterIPv4Route2,
					clusterIPv6Route2,
					loadBalancerIPv4Route,
					loadBalancerIPv6Route,
					podIPv4CIDRRoute,
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{updatedIPv4Peer2Config,
					updatedIPv6Peer2Config,
					ipv4Peer3Config,
					ipv6Peer3Config,
				},
				&confederationConfig{100, sets.New[uint32](uint32(65001))},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer3Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer3Config)
				mockBGPServer.RemovePeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.RemovePeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.UpdatePeer(gomock.Any(), updatedIPv4Peer2Config)
				mockBGPServer.UpdatePeer(gomock.Any(), updatedIPv6Peer2Config)
			},
		},
		{
			name: "Unrelated BGPPolicy, update NodeSelector (applied to current Node)",
			policyToUpdate: generateBGPPolicy(bgpPolicyName3,
				creationTimestampAdd2s,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			existingState: deepCopyBGPPolicyState(effectivePolicyState),
			expectedState: deepCopyBGPPolicyState(effectivePolicyState),
		},
		{
			name: "Alternative BGPPolicy, update Advertisements, LocalASN, ListenPort and BGPPeers",
			policyToUpdate: generateBGPPolicy(bgpPolicyName2,
				creationTimestampAdd1s,
				nodeLabels1,
				1179,
				65001,
				false,
				false,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					updatedIPv4Peer2,
					ipv6Peer1,
					updatedIPv6Peer2,
				}, &v1alpha1.Confederation{Identifier: 100, MemberASNs: []int32{65001}}),
			existingState: deepCopyBGPPolicyState(effectivePolicyState),
			expectedState: deepCopyBGPPolicyState(effectivePolicyState),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, objects, crdObjects, true, true)

			stopCh := make(chan struct{})
			defer close(stopCh)
			ctx := context.Background()
			c.startInformers(stopCh)

			// Wait for the dummy event triggered by BGPPolicy add events, and mark it done directly
			// since we fake the expected state.
			waitAndGetDummyEvent(t, c)
			doneDummyEvent(t, c)

			// Fake the BGPPolicy state the passwords of BGP peers.
			c.bgpPolicyState = deepCopyBGPPolicyState(effectivePolicyState)
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			c.bgpPeerPasswords = bgpPeerPasswords

			tt.policyToUpdate.Generation += 1
			_, err := c.crdClient.CrdV1alpha1().BGPPolicies().Update(context.TODO(), tt.policyToUpdate, metav1.UpdateOptions{})
			require.NoError(t, err)

			// Wait for the dummy event triggered by BGPPolicy update events.
			waitAndGetDummyEvent(t, c)

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			if tt.expectedError != "" {
				assert.EqualError(t, c.syncBGPPolicy(ctx), tt.expectedError)
			} else {
				assert.NoError(t, c.syncBGPPolicy(ctx))
			}
			// Done with the dummy event.
			doneDummyEvent(t, c)
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestBGPPolicyDelete(t *testing.T) {
	policy1 := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{
			ipv4Peer1,
			ipv6Peer1,
		},
		nil)
	policy1State := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{loadBalancerIPv4Route, loadBalancerIPv6Route},
		[]bgp.PeerConfig{
			ipv4Peer1Config,
			ipv6Peer1Config,
		},
		nil,
	)
	policy2 := generateBGPPolicy(bgpPolicyName2,
		creationTimestampAdd1s,
		nodeLabels1,
		179,
		65000,
		false,
		true,
		false,
		false,
		false,
		[]v1alpha1.BGPPeer{
			ipv4Peer2,
			ipv6Peer2,
		},
		nil,
	)
	policy2State := generateBGPPolicyState(bgpPolicyName2,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{externalIPv4Route2, externalIPv6Route2},
		[]bgp.PeerConfig{
			ipv4Peer2Config,
			ipv6Peer2Config},
		nil,
	)
	policy3 := generateBGPPolicy(bgpPolicyName3,
		creationTimestampAdd1s,
		nodeLabels1,
		1179,
		65000,
		false,
		true,
		false,
		false,
		false,
		[]v1alpha1.BGPPeer{
			ipv4Peer2,
			ipv6Peer2,
		},
		nil)
	policy3State := generateBGPPolicyState(bgpPolicyName3,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{externalIPv4Route2, externalIPv6Route2},
		[]bgp.PeerConfig{
			ipv4Peer2Config,
			ipv6Peer2Config},
		nil,
	)
	objects := []runtime.Object{
		ipv4LoadBalancer,
		ipv4LoadBalancerEps,
		ipv6LoadBalancer,
		ipv6LoadBalancerEps,
		node,
	}
	testCases := []struct {
		name           string
		policyToDelete string
		crdObjects     []runtime.Object
		existingState  *bgpPolicyState
		expectedState  *bgpPolicyState
		expectedCalls  func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name:           "Delete effective BGPPolicy and there is no alternative one",
			policyToDelete: bgpPolicyName1,
			crdObjects:     []runtime.Object{policy1},
			existingState:  deepCopyBGPPolicyState(policy1State),
			expectedState:  nil,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
			},
		},
		{
			name:           "Delete effective BGPPolicy and there is an alternative one, not need to start new BGP server",
			policyToDelete: bgpPolicyName1,
			crdObjects:     []runtime.Object{policy1, policy2},
			existingState:  deepCopyBGPPolicyState(policy1State),
			expectedState:  deepCopyBGPPolicyState(policy2State),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.RemovePeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.RemovePeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv6Route2})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
				mockBGPServer.WithdrawRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv6Route})
			},
		},
		{
			name:           "Delete effective BGPPolicy and there is an alternative one, need to start new BGP server",
			policyToDelete: bgpPolicyName1,
			crdObjects:     []runtime.Object{policy1, policy3},
			existingState:  deepCopyBGPPolicyState(policy1State),
			expectedState:  deepCopyBGPPolicyState(policy3State),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer2Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer2Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv6Route2})
			},
		},
		{
			name:           "Delete an alternative BGPPolicy",
			policyToDelete: bgpPolicyName2,
			crdObjects:     []runtime.Object{policy1, policy2},
			existingState:  deepCopyBGPPolicyState(policy1State),
			expectedState:  deepCopyBGPPolicyState(policy1State),
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, objects, tt.crdObjects, true, true)

			stopCh := make(chan struct{})
			defer close(stopCh)
			ctx := context.Background()
			c.startInformers(stopCh)

			// Wait for the dummy event triggered by BGPPolicy add events, and mark it done.
			waitAndGetDummyEvent(t, c)
			doneDummyEvent(t, c)

			// Fake the BGPPolicy state and the passwords of BGP peers.
			c.bgpPolicyState = tt.existingState
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			c.bgpPeerPasswords = bgpPeerPasswords

			err := c.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), tt.policyToDelete, metav1.DeleteOptions{})
			require.NoError(t, err)

			// Wait for the dummy event triggered by BGPPolicy delete events.
			waitAndGetDummyEvent(t, c)

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			assert.NoError(t, c.syncBGPPolicy(ctx))
			// Done with the dummy event.
			doneDummyEvent(t, c)
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestNodeUpdate(t *testing.T) {
	policy1 := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1},
		nil)
	policy1State := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{podIPv4CIDRRoute, podIPv6CIDRRoute},
		[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
		nil)
	policy2 := generateBGPPolicy(bgpPolicyName2,
		creationTimestampAdd1s,
		nodeLabels2,
		1179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1},
		nil)
	policy2State := generateBGPPolicyState(bgpPolicyName2,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{podIPv4CIDRRoute, podIPv6CIDRRoute},
		[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
		nil)
	policy3 := generateBGPPolicy(bgpPolicyName3,
		creationTimestampAdd2s,
		nodeLabels3,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1},
		nil)
	crdObjects := []runtime.Object{
		policy1,
		policy2,
		policy3,
	}
	testCases := []struct {
		name          string
		ipv4Enabled   bool
		ipv6Enabled   bool
		node          *corev1.Node
		updatedNode   *corev1.Node
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name:          "Update labels, a BGPPolicy is added to alternatives",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels3, nodeAnnotations1),
			existingState: deepCopyBGPPolicyState(policy1State),
			expectedState: deepCopyBGPPolicyState(policy1State),
		},
		{
			name:          "Update labels, a BGPPolicy is removed from alternatives",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels3, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			existingState: deepCopyBGPPolicyState(policy1State),
			expectedState: deepCopyBGPPolicyState(policy1State),
		},
		{
			name:          "Update labels, effective BGPPolicy is updated to another one",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels2, nodeAnnotations1),
			existingState: deepCopyBGPPolicyState(policy1State),
			expectedState: deepCopyBGPPolicyState(policy2State),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name:        "Update labels, effective BGPPolicy is updated to empty",
			ipv4Enabled: true,
			ipv6Enabled: true,
			node:        generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode: generateNode(localNodeName, nil, nodeAnnotations1),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any())
			},
			existingState: deepCopyBGPPolicyState(policy1State),
		},
		{
			name:          "Update annotations, effective BGPPolicy router ID is updated",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels1, nodeAnnotations2),
			existingState: deepCopyBGPPolicyState(policy1State),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations2[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{podIPv4CIDRRoute, podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name:          "Remove annotations, router ID is updated using Node's IPv4 address",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels1, nil),
			existingState: deepCopyBGPPolicyState(policy1State),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]bgp.Route{podIPv4CIDRRoute, podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv4Peer1Config)
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name:        "IPv6 only, update annotations, effective BGPPolicy router ID is updated",
			ipv6Enabled: true,
			node:        generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode: generateNode(localNodeName, nodeLabels1, nodeAnnotations2),
			existingState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations2[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
		{
			name:        "IPv6 only, remove annotations, router ID is generated from Node name ",
			ipv6Enabled: true,
			node:        generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode: generateNode(localNodeName, nodeLabels1, nil),
			existingState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				[]bgp.Route{
					podIPv6CIDRRoute,
				},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				"156.67.103.8",
				[]bgp.Route{podIPv6CIDRRoute},
				[]bgp.PeerConfig{ipv6Peer1Config},
				nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.Stop(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv6CIDRRoute})
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, crdObjects, tt.ipv4Enabled, tt.ipv6Enabled)

			stopCh := make(chan struct{})
			defer close(stopCh)
			ctx := context.Background()
			c.startInformers(stopCh)

			// Fake the passwords of BGP peers.
			c.bgpPeerPasswords = bgpPeerPasswords

			// Initializing BGPPolicy objects will not trigger a dummy event because the local Node object has not been
			// initialized and synced yet. The dummy event will be trigger by adding the local Node object.
			_, err := c.client.CoreV1().Nodes().Create(context.TODO(), tt.node, metav1.CreateOptions{})
			require.NoError(t, err)

			// Wait for the dummy event triggered by Node add event.
			waitAndGetDummyEvent(t, c)
			doneDummyEvent(t, c)

			// Fake the BGPPolicy state.
			c.bgpPolicyState = tt.existingState
			c.bgpPolicyState.bgpServer = c.mockBGPServer

			_, err = c.client.CoreV1().Nodes().Update(context.TODO(), tt.updatedNode, metav1.UpdateOptions{})
			require.NoError(t, err)

			// Wait for the dummy event triggered by Node update events.
			waitAndGetDummyEvent(t, c)

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			assert.NoError(t, c.syncBGPPolicy(ctx))
			// Done with the dummy event.
			doneDummyEvent(t, c)
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
			if !tt.ipv4Enabled && tt.ipv6Enabled {
				updatedNode, err := c.client.CoreV1().Nodes().Get(context.TODO(), localNodeName, metav1.GetOptions{})
				require.NoError(t, err)
				require.NotNil(t, updatedNode.Annotations)
				assert.Equal(t, tt.expectedState.routerID, updatedNode.Annotations[types.NodeBGPRouterIDAnnotationKey])
			}
		})
	}
}

func TestServiceLifecycle(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		true,
		true,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer1},
		nil)
	c := newFakeController(t, []runtime.Object{node}, []runtime.Object{policy}, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)
	ctx := context.Background()
	c.startInformers(stopCh)

	// Fake the passwords of BGP peers.
	c.bgpPeerPasswords = bgpPeerPasswords

	// Wait for the dummy event triggered by BGPPolicy add events.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().Start(gomock.Any())
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config)
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)

	// Create a Service configured with both `internalTrafficPolicy` and `externalTrafficPolicy` set to `Local`.
	loadBalancer := generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.100", "192.168.77.150", true, true)
	_, err := c.client.CoreV1().Services(namespaceDefault).Create(context.TODO(), loadBalancer, metav1.CreateOptions{})
	require.NoError(t, err)

	// Add an EndpointSlice without Endpoint IP for the Service. This could be happened at the moment after a Service is
	// just created.
	endpointSlice := generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, true, false, "")
	_, err = c.client.DiscoveryV1().EndpointSlices(namespaceDefault).Create(context.TODO(), endpointSlice, metav1.CreateOptions{})
	require.NoError(t, err)

	// Since both `internalTrafficPolicy` and `externalTrafficPolicy` are `Local` and no local Endpoint, no Service IP
	// will be advertised.
	waitAndGetDummyEvent(t, c)
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update the EndpointSlice with a local Endpoint IP.
	endpointSlice = generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, true, false, "10.10.0.2")
	_, err = c.client.DiscoveryV1().EndpointSlices(namespaceDefault).Update(context.TODO(), endpointSlice, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Since there is a local Endpoint IP and both `internalTrafficPolicy` and `externalTrafficPolicy` are `Local`, the
	// ClusterIP, externalIP, and LoadBalancerIP will be advertised.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "10.96.10.10/32"}})
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.100/32"}})
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.150/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update externalIP and LoadBalancerIP of the Service. Additionally, update both `externalTrafficPolicy` and
	// `internalTrafficPolicy` to `Cluster`.
	updatedLoadBalancer := generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", false, false)
	_, err = c.client.CoreV1().Services(namespaceDefault).Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// The stale externalIP and LoadBalancerIP will be withdrawn. The new externalIP and LoadBalancerIP will be advertised.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.151/32"}})
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.101/32"}})
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.100/32"}})
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.150/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update `externalTrafficPolicy` of the Service from `Cluster` to `Local`.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", false, true)
	_, err = c.client.CoreV1().Services(namespaceDefault).Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Update the EndpointSlice with a remote Endpoint.
	endpointSlice = generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, false, false, "10.10.0.3")
	_, err = c.client.DiscoveryV1().EndpointSlices(namespaceDefault).Update(context.TODO(), endpointSlice, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Since there is no local Endpoint and `externalTrafficPolicy` is `Local`, the externalIP and LoadBalancerIP will be
	// withdrawn.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.101/32"}})
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.151/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update `internalTrafficPolicy` of the Service from `Cluster` to `Local`.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", true, true)
	_, err = c.client.CoreV1().Services(namespaceDefault).Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Since there is no local Endpoint and `internalTrafficPolicy` is `Local`, the ClusterIP will be withdrawn.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "10.96.10.10/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update `externalTrafficPolicy` of the Service from `Local` to `Cluster`.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", true, false)
	_, err = c.client.CoreV1().Services(namespaceDefault).Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Since `externalTrafficPolicy` is `Cluster`, the ClusterIP will be advertised even if there is no local Endpoint.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.101/32"}})
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.151/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Delete the Service.
	err = c.client.CoreV1().Services(namespaceDefault).Delete(context.TODO(), updatedLoadBalancer.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// Since the Service is deleted, all corresponding Service IPs will be withdrawn.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.101/32"}})
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: "192.168.77.151/32"}})
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)
}

func TestEgressLifecycle(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		true,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer1},
		nil)
	c := newFakeController(t, []runtime.Object{node}, []runtime.Object{policy}, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)
	ctx := context.Background()
	c.startInformers(stopCh)

	// Fake the passwords of BGP peers.
	c.bgpPeerPasswords = bgpPeerPasswords

	// Wait for the dummy event triggered by BGPPolicy add events,.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().Start(gomock.Any())
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config)
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)

	// Create an Egress.
	egress := generateEgress("eg1-4", "192.168.77.200", localNodeName)
	_, err := c.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err)

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.200/32"}}))
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update the Egress.
	updatedEgress := generateEgress("eg1-4", "192.168.77.201", localNodeName)
	_, err = c.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), updatedEgress, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.200/32"}}))
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update the Egress.
	updatedEgress = generateEgress("eg1-4", "192.168.77.201", "remote")
	_, err = c.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), updatedEgress, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Update the Egress.
	updatedEgress = generateEgress("eg1-4", "192.168.77.201", localNodeName)
	_, err = c.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), updatedEgress, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)

	// Delete the Egress.
	err = c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), updatedEgress.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)
}

func TestBGPPasswordUpdate(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv4Peer2, ipv4Peer3},
		nil)
	c := newFakeController(t, []runtime.Object{node}, []runtime.Object{policy}, true, false)

	c.secretInformer = coreinformers.NewFilteredSecretInformer(c.client,
		namespaceKubeSystem,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.BGPPolicySecretName).String()
		})
	c.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addSecret,
		UpdateFunc: c.updateSecret,
		DeleteFunc: c.deleteSecret,
	})
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)
	ctx := context.Background()
	c.startInformers(stopCh)
	go c.secretInformer.Run(stopCh)

	// Create the Secret.
	secret := generateSecret(bgpPeerPasswords)
	_, err := c.client.CoreV1().Secrets(namespaceKubeSystem).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		c.bgpPeerPasswordsMutex.RLock()
		defer c.bgpPeerPasswordsMutex.RUnlock()
		return reflect.DeepEqual(c.bgpPeerPasswords, bgpPeerPasswords)
	}, 5*time.Second, 10*time.Millisecond)

	// Wait for the dummy event triggered by BGPPolicy add events.
	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().Start(gomock.Any())
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config)
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer2Config)
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer3Config)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)

	// Update the Secret.
	updatedBGPPeerPasswords := map[string]string{
		generateBGPPeerKey(ipv4Peer1Addr, peer1ASN): "updated-" + peer1AuthPassword,
		generateBGPPeerKey(ipv4Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv4Peer3Addr, peer3ASN): "updated-" + peer3AuthPassword,
	}
	updatedSecret := generateSecret(updatedBGPPeerPasswords)
	_, err = c.client.CoreV1().Secrets(namespaceKubeSystem).Update(context.TODO(), updatedSecret, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		c.bgpPeerPasswordsMutex.RLock()
		defer c.bgpPeerPasswordsMutex.RUnlock()
		return reflect.DeepEqual(c.bgpPeerPasswords, updatedBGPPeerPasswords)
	}, 5*time.Second, 10*time.Millisecond)

	// Wait for the dummy event triggered by Secret update event, and mark it done.
	waitAndGetDummyEvent(t, c)
	expectedIPv4Peer1Config := ipv4Peer1Config
	expectedIPv4Peer3Config := ipv4Peer3Config
	expectedIPv4Peer1Config.Password = "updated-" + peer1AuthPassword
	expectedIPv4Peer3Config.Password = "updated-" + peer3AuthPassword
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), expectedIPv4Peer1Config)
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), expectedIPv4Peer3Config)
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)

	// Delete the Secret.
	err = c.client.CoreV1().Secrets(namespaceKubeSystem).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	// Wait for the dummy event triggered by Secret delete event, and mark it done.
	waitAndGetDummyEvent(t, c)
	expectedIPv4Peer1Config = ipv4Peer1Config
	expectedIPv4Peer2Config := ipv4Peer2Config
	expectedIPv4Peer3Config = ipv4Peer3Config
	expectedIPv4Peer1Config.Password = ""
	expectedIPv4Peer2Config.Password = ""
	expectedIPv4Peer3Config.Password = ""
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), expectedIPv4Peer1Config)
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), expectedIPv4Peer2Config)
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), expectedIPv4Peer3Config)
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)
}

func TestSyncBGPPolicyFailures(t *testing.T) {
	policy1 := generateBGPPolicy(bgpPolicyName1,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer2},
		nil)
	policy2 := generateBGPPolicy(bgpPolicyName2,
		creationTimestampAdd1s,
		nodeLabels1,
		1179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1},
		nil)
	policy3 := generateBGPPolicy(bgpPolicyName3,
		creationTimestampAdd2s,
		nodeLabels1,
		1179,
		65000,
		false,
		true,
		false,
		false,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer2},
		nil)
	policy4 := generateBGPPolicy(bgpPolicyName4,
		creationTimestampAdd3s,
		nodeLabels1,
		1179,
		65000,
		false,
		false,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{updatedIPv4Peer2},
		nil)
	objects := []runtime.Object{
		ipv4LoadBalancer,
		ipv4LoadBalancerEps,
		ipv6LoadBalancer,
		ipv6LoadBalancerEps,
		node,
	}
	crdObjects := []runtime.Object{
		policy1,
		policy2,
		policy3,
		policy4,
	}

	c := newFakeController(t, objects, crdObjects, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)
	ctx := context.Background()
	c.startInformers(stopCh)

	// Wait for the dummy event triggered by BGPPolicy ADD events.
	waitAndGetDummyEvent(t, c)

	// Fake the passwords of BGP peers.
	c.bgpPeerPasswords = bgpPeerPasswords

	mockBGPServer.EXPECT().Start(gomock.Any())
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer2Config)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})
	require.NoError(t, c.syncBGPPolicy(ctx))
	// Done with the dummy event.
	doneDummyEvent(t, c)

	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{loadBalancerIPv4Route},
		[]bgp.PeerConfig{ipv4Peer2Config},
		nil),
		c.bgpPolicyState)

	// Delete the effective BGPPolicy policy1, and BGPPolicy policy2 will be the effective one.
	require.NoError(t, c.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), policy1.Name, metav1.DeleteOptions{}))

	waitAndGetDummyEvent(t, c)

	// The local ASN of BGPPolicy policy2 is different from BGPPolicy policy1, and the current BGP server should be stopped.
	// Mock that failing in stopping the current BGP server.
	mockBGPServer.EXPECT().Stop(gomock.Any()).Return(fmt.Errorf("failed reason"))
	require.EqualError(t, c.syncBGPPolicy(ctx), "failed to stop current BGP server: failed reason")
	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{loadBalancerIPv4Route},
		[]bgp.PeerConfig{ipv4Peer2Config}, nil), c.bgpPolicyState)

	// Mock the retry. Stop the current BGP server successfully, but fail in starting a new BGP server.
	mockBGPServer.EXPECT().Stop(gomock.Any())
	mockBGPServer.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("failed reason"))
	require.EqualError(t, c.syncBGPPolicy(ctx), "failed to start BGP server: failed reason")
	checkBGPPolicyState(t, nil, c.bgpPolicyState)

	// Mock the retry. Start BGP server successfully, but fail in adding BGP peer.
	mockBGPServer.EXPECT().Start(gomock.Any())
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config).Return(fmt.Errorf("failed to add BGP peer"))
	require.EqualError(t, c.syncBGPPolicy(ctx), "failed to add BGP peer")
	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName2,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{},
		[]bgp.PeerConfig{},
		nil),
		c.bgpPolicyState)

	// Mock the retry. Add the BGP peer successfully, but fail in advertising routes.
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute}).Return(fmt.Errorf("failed to advertise routes"))
	require.EqualError(t, c.syncBGPPolicy(ctx), "failed to advertise routes")
	// Done with the dummy event.
	doneDummyEvent(t, c)
	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName2,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{},
		[]bgp.PeerConfig{ipv4Peer1Config},
		nil),
		c.bgpPolicyState)

	// Delete the effective BGPPolicy policy2, and BGPPolicy policy3 will be the effective one. The BGP server doesn't need to
	// be updated. The peers and routes will be reconciled according to the existing BGPPolicy state.
	require.NoError(t, c.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), policy2.Name, metav1.DeleteOptions{}))

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer2Config)
	mockBGPServer.EXPECT().RemovePeer(gomock.Any(), ipv4Peer1Config)
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})

	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)
	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName3,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{externalIPv4Route2},
		[]bgp.PeerConfig{ipv4Peer2Config},
		nil),
		c.bgpPolicyState)

	// Delete the effective BGPPolicy policy3, and BGPPolicy policy4 will be the effective one. The BGP server doesn't need to
	// be updated. The peers and routes will be reconciled according to the existing BGPPolicy state.
	require.NoError(t, c.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), policy3.Name, metav1.DeleteOptions{}))

	waitAndGetDummyEvent(t, c)
	mockBGPServer.EXPECT().UpdatePeer(gomock.Any(), updatedIPv4Peer2Config)
	mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{externalIPv4Route2})
	mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{loadBalancerIPv4Route})

	require.NoError(t, c.syncBGPPolicy(ctx))
	doneDummyEvent(t, c)
	checkBGPPolicyState(t, generateBGPPolicyState(bgpPolicyName4,
		1179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{loadBalancerIPv4Route},
		[]bgp.PeerConfig{updatedIPv4Peer2Config},
		nil),
		c.bgpPolicyState)
}

func generateBGPPolicyState(bgpPolicyName string,
	listenPort int32,
	localASN int32,
	routerID string,
	bgpRoutes []bgp.Route,
	peerConfigs []bgp.PeerConfig,
	confederationConfig *confederationConfig) *bgpPolicyState {
	routes := map[bgp.Route]RouteMetadata{}
	peerConfigMap := make(map[string]bgp.PeerConfig)
	for _, route := range bgpRoutes {
		routes[route] = allRoutes[route]
	}
	for _, peerConfig := range peerConfigs {
		peerKey := generateBGPPeerKey(peerConfig.Address, peerConfig.ASN)
		peerConfigMap[peerKey] = peerConfig
	}
	state := &bgpPolicyState{
		bgpPolicyName:       bgpPolicyName,
		listenPort:          listenPort,
		localASN:            localASN,
		routerID:            routerID,
		confederationConfig: confederationConfig,
		routes:              routes,
		peerConfigs:         peerConfigMap,
	}
	return state
}

func deepCopyBGPPolicyState(in *bgpPolicyState) *bgpPolicyState {
	peerConfigMap := make(map[string]bgp.PeerConfig)
	for _, peerConfig := range in.peerConfigs {
		peerKey := generateBGPPeerKey(peerConfig.Address, peerConfig.ASN)
		peerConfigMap[peerKey] = peerConfig
	}
	routes := make(map[bgp.Route]RouteMetadata)
	for routeType := range in.routes {
		routes[routeType] = in.routes[routeType]
	}
	var confederationConf *confederationConfig
	if in.confederationConfig != nil {
		confederationConf = &confederationConfig{
			identifier: in.confederationConfig.identifier,
			memberASNs: in.confederationConfig.memberASNs.Clone(),
		}
	}

	return &bgpPolicyState{
		bgpPolicyName:       in.bgpPolicyName,
		listenPort:          in.listenPort,
		localASN:            in.localASN,
		routerID:            in.routerID,
		confederationConfig: confederationConf,
		routes:              routes,
		peerConfigs:         peerConfigMap,
	}
}

func checkBGPPolicyState(t *testing.T, expected, got *bgpPolicyState) {
	require.Equal(t, expected != nil, got != nil)
	if expected != nil {
		assert.Equal(t, expected.bgpPolicyName, got.bgpPolicyName)
		assert.Equal(t, expected.listenPort, got.listenPort)
		assert.Equal(t, expected.localASN, got.localASN)
		assert.Equal(t, expected.routerID, got.routerID)
		assert.Equal(t, expected.routes, got.routes)
		assert.Equal(t, expected.peerConfigs, got.peerConfigs)
		assert.Equal(t, expected.confederationConfig, got.confederationConfig)
	}
}

func generateBGPPolicy(name string,
	creationTimestamp metav1.Time,
	nodeSelector map[string]string,
	listenPort int32,
	localASN int32,
	advertiseClusterIP bool,
	advertiseExternalIP bool,
	advertiseLoadBalancerIP bool,
	advertiseEgressIP bool,
	advertisePodCIDR bool,
	externalPeers []v1alpha1.BGPPeer,
	confederation *v1alpha1.Confederation) *v1alpha1.BGPPolicy {
	var advertisement v1alpha1.Advertisements
	advertisement.Service = &v1alpha1.ServiceAdvertisement{}
	if advertiseClusterIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeClusterIP)
	}
	if advertiseExternalIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeExternalIP)
	}
	if advertiseLoadBalancerIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeLoadBalancerIP)
	}
	if advertiseEgressIP {
		advertisement.Egress = &v1alpha1.EgressAdvertisement{}
	}

	if advertisePodCIDR {
		advertisement.Pod = &v1alpha1.PodAdvertisement{}
	}
	bgpPolicy := &v1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			UID:               "test-uid",
			CreationTimestamp: creationTimestamp,
		},
		Spec: v1alpha1.BGPPolicySpec{
			NodeSelector:   metav1.LabelSelector{MatchLabels: nodeSelector},
			LocalASN:       localASN,
			ListenPort:     &listenPort,
			Confederation:  confederation,
			Advertisements: advertisement,
			BGPPeers:       externalPeers,
		},
	}
	return bgpPolicy
}

func generateService(name string,
	svcType corev1.ServiceType,
	clusterIP string,
	externalIP string,
	LoadBalancerIP string,
	internalTrafficPolicyLocal bool,
	externalTrafficPolicyLocal bool) *corev1.Service {
	itp := corev1.ServiceInternalTrafficPolicyCluster
	if internalTrafficPolicyLocal {
		itp = corev1.ServiceInternalTrafficPolicyLocal
	}
	etp := corev1.ServiceExternalTrafficPolicyCluster
	if externalTrafficPolicyLocal {
		etp = corev1.ServiceExternalTrafficPolicyLocal
	}
	var externalIPs []string
	if externalIP != "" {
		externalIPs = append(externalIPs, externalIP)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespaceDefault,
			UID:       "test-uid",
		},
		Spec: corev1.ServiceSpec{
			Type:      svcType,
			ClusterIP: clusterIP,
			Ports: []corev1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: corev1.ProtocolTCP,
			}},
			ClusterIPs:            []string{clusterIP},
			ExternalIPs:           externalIPs,
			InternalTrafficPolicy: &itp,
			ExternalTrafficPolicy: etp,
		},
	}
	if LoadBalancerIP != "" {
		ingress := []corev1.LoadBalancerIngress{{IP: LoadBalancerIP}}
		svc.Status.LoadBalancer.Ingress = ingress
	}
	return svc
}

func generateEgress(name string, ip string, nodeName string) *crdv1b1.Egress {
	return &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  "test-uid",
		},
		Spec: crdv1b1.EgressSpec{
			EgressIP: ip,
		},
		Status: crdv1b1.EgressStatus{
			EgressIP:   ip,
			EgressNode: nodeName,
		},
	}
}

func generateNode(name string, labels, annotations map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			UID:         "test-uid",
			Labels:      labels,
			Annotations: annotations,
		},
	}
}

func generateEndpointSlice(svcName string,
	suffix string,
	isLocal bool,
	isIPv6 bool,
	endpointIP string) *discovery.EndpointSlice {
	addrType := discovery.AddressTypeIPv4
	if isIPv6 {
		addrType = discovery.AddressTypeIPv6
	}
	var nodeName *string
	if isLocal {
		nodeName = &localNodeName
	}
	protocol := corev1.ProtocolTCP
	endpointSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", svcName, suffix),
			Namespace: namespaceDefault,
			UID:       "test-uid",
			Labels: map[string]string{
				discovery.LabelServiceName: svcName,
			},
		},
		AddressType: addrType,
	}
	if endpointIP != "" {
		endpointSlice.Endpoints = []discovery.Endpoint{{
			Addresses: []string{
				endpointIP,
			},
			Conditions: discovery.EndpointConditions{
				Ready: ptr.To(true),
			},
			Hostname: nodeName,
			NodeName: nodeName,
		}}
		endpointSlice.Ports = []discovery.EndpointPort{{
			Name:     ptr.To("p80"),
			Port:     ptr.To(int32(80)),
			Protocol: &protocol,
		}}
	}
	return endpointSlice
}

func generateBGPPeer(ip string, asn, port, gracefulRestartTimeSeconds int32) v1alpha1.BGPPeer {
	return v1alpha1.BGPPeer{
		Address:                    ip,
		Port:                       &port,
		ASN:                        asn,
		MultihopTTL:                ptr.To(int32(1)),
		GracefulRestartTimeSeconds: &gracefulRestartTimeSeconds,
	}
}

func generateBGPPeerConfig(peerConfig *v1alpha1.BGPPeer, password string) bgp.PeerConfig {
	return bgp.PeerConfig{
		BGPPeer:  peerConfig,
		Password: password,
	}
}

func generateSecret(rawData map[string]string) *corev1.Secret {
	data := make(map[string][]byte)
	for k, v := range rawData {
		data[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      types.BGPPolicySecretName,
			Namespace: namespaceKubeSystem,
			UID:       "test-uid",
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

func ipStrToPrefix(ipStr string) string {
	if utilnet.IsIPv4String(ipStr) {
		return ipStr + ipv4Suffix
	} else if utilnet.IsIPv6String(ipStr) {
		return ipStr + ipv6Suffix
	}
	return ""
}

func waitAndGetDummyEvent(t *testing.T, c *fakeController) {
	require.Eventually(t, func() bool {
		return c.queue.Len() == 1
	}, 5*time.Second, 10*time.Millisecond)
	c.queue.Get()
}
func doneDummyEvent(t *testing.T, c *fakeController) {
	c.queue.Done(dummyKey)
}
func getServiceName(name string) string {
	return namespaceDefault + "/" + name
}

func TestGetBGPPolicyInfo(t *testing.T) {
	testCases := []struct {
		name                            string
		existingState                   *bgpPolicyState
		expectedBgpPolicyName           string
		expectedASN                     int32
		expectedRouterID                string
		expectedListenPort              int32
		expectedConfederationIdentifier int32
	}{
		{
			name: "bgpPolicyState exists",
			existingState: generateBGPPolicyState(bgpPolicyName1,
				179,
				64512,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				nil,
				nil,
				nil,
			),
			expectedBgpPolicyName: bgpPolicyName1,
			expectedASN:           int32(64512),
			expectedRouterID:      nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
			expectedListenPort:    int32(179),
		},
		{
			name: "bgpPolicyState exists with confederation",
			existingState: generateBGPPolicyState(bgpPolicyName1,
				179,
				64512,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
				nil,
				nil,
				&confederationConfig{identifier: int32(65000)},
			),
			expectedBgpPolicyName:           bgpPolicyName1,
			expectedASN:                     int32(64512),
			expectedRouterID:                nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
			expectedListenPort:              int32(179),
			expectedConfederationIdentifier: int32(65000),
		},
		{
			name:          "bgpPolicyState does not exist",
			existingState: nil,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, nil, true, false)

			// Fake the BGPPolicy state.
			c.bgpPolicyState = tt.existingState

			actualBgpPolicyName, actualRouterID, actualASN, actualListenPort, actualConfederationIdentifier := c.GetBGPPolicyInfo()
			assert.Equal(t, tt.expectedBgpPolicyName, actualBgpPolicyName)
			assert.Equal(t, tt.expectedRouterID, actualRouterID)
			assert.Equal(t, tt.expectedASN, actualASN)
			assert.Equal(t, tt.expectedListenPort, actualListenPort)
			assert.Equal(t, tt.expectedConfederationIdentifier, actualConfederationIdentifier)
		})
	}
}

func TestGetBGPPeerStatus(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                  string
		existingState         *bgpPolicyState
		expectedCalls         func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectedBgpPeerStatus []bgp.PeerStatus
		expectedErr           error
	}{
		{
			name:          "get bgp peers status",
			existingState: &bgpPolicyState{},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.GetPeers(ctx).Return([]bgp.PeerStatus{ipv4Peer1Status, ipv4Peer2Status,
					ipv6Peer1Status, ipv6Peer2Status}, nil)
			},
			expectedBgpPeerStatus: []bgp.PeerStatus{ipv4Peer1Status, ipv4Peer2Status, ipv6Peer1Status, ipv6Peer2Status},
		},
		{
			name:        "bgpPolicyState does not exist",
			expectedErr: ErrBGPPolicyNotFound,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, nil, true, true)

			// Fake the BGPPolicy state.
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}

			actualBgpPeerStatus, err := c.GetBGPPeerStatus(ctx)
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBgpPeerStatus, actualBgpPeerStatus)
			}
		})
	}
}

func TestGetBGPRoutes(t *testing.T) {
	effectivePolicyState := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey],
		[]bgp.Route{clusterIPv4Route1, clusterIPv6Route1, loadBalancerIPv4Route,
			loadBalancerIPv6Route, podIPv4CIDRRoute, podIPv6CIDRRoute},
		[]bgp.PeerConfig{},
		nil,
	)
	ctx := context.Background()
	testCases := []struct {
		name              string
		existingState     *bgpPolicyState
		expectedBgpRoutes map[bgp.Route]RouteMetadata
		expectedErr       string
	}{
		{
			name:          "get advertised routes",
			existingState: effectivePolicyState,
			expectedBgpRoutes: map[bgp.Route]RouteMetadata{
				clusterIPv4Route1:     allRoutes[clusterIPv4Route1],
				clusterIPv6Route1:     allRoutes[clusterIPv6Route1],
				loadBalancerIPv4Route: allRoutes[loadBalancerIPv4Route],
				loadBalancerIPv6Route: allRoutes[loadBalancerIPv6Route],
				podIPv4CIDRRoute:      allRoutes[podIPv4CIDRRoute],
				podIPv6CIDRRoute:      allRoutes[podIPv6CIDRRoute],
			},
		},
		{
			name:        "bgpPolicyState does not exist",
			expectedErr: ErrBGPPolicyNotFound.Error(),
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, nil, true, true)

			// Fake the BGPPolicy state.
			c.bgpPolicyState = tt.existingState

			actualBgpRoutes, err := c.GetBGPRoutes(ctx)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBgpRoutes, actualBgpRoutes)
			}
		})
	}
}
