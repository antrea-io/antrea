// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/features"
)

func TestToAntreaServicesForCRD(t *testing.T) {
	igmpQuery := int32(17)
	igmpReport := int32(18)
	queryStr := "224.0.0.1"
	reportStr := "225.1.2.3"
	tables := []struct {
		ports              []crdv1beta1.NetworkPolicyPort
		protocols          []crdv1beta1.NetworkPolicyProtocol
		expServices        []controlplane.Service
		expNamedPortExists bool
	}{
		{
			ports: []crdv1beta1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int80,
				},
			},
			expNamedPortExists: false,
		},
		{
			ports: []crdv1beta1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &strHTTP,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &strHTTP,
				},
			},
			expNamedPortExists: true,
		},
		{
			ports: []crdv1beta1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int1000,
					EndPort:  &int32For1999,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int1000,
					EndPort:  &int32For1999,
				},
			},
			expNamedPortExists: false,
		},
		{
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					ICMP: &crdv1beta1.ICMPProtocol{
						ICMPType: &icmpType8,
						ICMPCode: &icmpCode0,
					},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: &protocolICMP,
					ICMPType: &icmpType8,
					ICMPCode: &icmpCode0,
				},
			},
			expNamedPortExists: false,
		},
		{
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					IGMP: &crdv1beta1.IGMPProtocol{
						IGMPType:     &igmpQuery,
						GroupAddress: queryStr,
					},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol:     &protocolIGMP,
					IGMPType:     &igmpQuery,
					GroupAddress: queryStr,
				},
			},
		},
		{
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					IGMP: &crdv1beta1.IGMPProtocol{
						IGMPType:     &igmpReport,
						GroupAddress: reportStr,
					},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol:     &protocolIGMP,
					IGMPType:     &igmpReport,
					GroupAddress: reportStr,
				},
			},
		},
		{
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					ICMP: &crdv1beta1.ICMPProtocol{
						ICMPType: &icmpType8,
					},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: &protocolICMP,
					ICMPType: &icmpType8,
				},
			},
			expNamedPortExists: false,
		},
		{
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					ICMP: &crdv1beta1.ICMPProtocol{},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: &protocolICMP,
				},
			},
			expNamedPortExists: false,
		},
		{
			ports: []crdv1beta1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			protocols: []crdv1beta1.NetworkPolicyProtocol{
				{
					ICMP: &crdv1beta1.ICMPProtocol{
						ICMPType: &icmpType8,
						ICMPCode: &icmpCode0,
					},
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int80,
				},
				{
					Protocol: &protocolICMP,
					ICMPType: &icmpType8,
					ICMPCode: &icmpCode0,
				},
			},
			expNamedPortExists: false,
		},
	}
	for _, table := range tables {
		services, namedPortExist := toAntreaServicesForCRD(table.ports, table.protocols)
		assert.Equal(t, table.expServices, services)
		assert.Equal(t, table.expNamedPortExists, namedPortExist)
	}
}

func TestToAntreaL7ProtocolsForCRD(t *testing.T) {
	tables := []struct {
		l7Protocol []crdv1beta1.L7Protocol
		expValue   []controlplane.L7Protocol
	}{
		{
			[]crdv1beta1.L7Protocol{
				{HTTP: &crdv1beta1.HTTPProtocol{Host: "test.com", Method: "GET", Path: "/admin"}},
			},
			[]controlplane.L7Protocol{
				{HTTP: &controlplane.HTTPProtocol{Host: "test.com", Method: "GET", Path: "/admin"}},
			},
		},
		{
			[]crdv1beta1.L7Protocol{
				{TLS: &crdv1beta1.TLSProtocol{SNI: "test.com"}},
			},
			[]controlplane.L7Protocol{
				{TLS: &controlplane.TLSProtocol{SNI: "test.com"}},
			},
		},
	}
	for _, table := range tables {
		gotValue := toAntreaL7ProtocolsForCRD(table.l7Protocol)
		assert.Equal(t, table.expValue, gotValue)
	}
}

func TestToAntreaIPBlockForCRD(t *testing.T) {
	expIPNet := controlplane.IPNet{
		IP:           ipStrToIPAddress("10.0.0.0"),
		PrefixLength: 24,
	}
	tables := []struct {
		ipBlock  *crdv1beta1.IPBlock
		expValue controlplane.IPBlock
		err      error
	}{
		{
			&crdv1beta1.IPBlock{
				CIDR: "10.0.0.0/24",
			},
			controlplane.IPBlock{
				CIDR: expIPNet,
			},
			nil,
		},
		{
			&crdv1beta1.IPBlock{
				CIDR: "10.0.0.0",
			},
			controlplane.IPBlock{},
			fmt.Errorf("invalid format for IPBlock CIDR: 10.0.0.0"),
		},
	}
	for _, table := range tables {
		antreaIPBlock, err := toAntreaIPBlockForCRD(table.ipBlock)
		if err != nil {
			if err.Error() != table.err.Error() {
				t.Errorf("Unexpected error in Antrea IPBlock conversion. Expected %v, got %v", table.err, err)
			}
		}
		if antreaIPBlock == nil {
			continue
		}
		ipNet := antreaIPBlock.CIDR
		if bytes.Compare(ipNet.IP, table.expValue.CIDR.IP) != 0 {
			t.Errorf("Unexpected IP in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.IP, ipNet.IP)
		}
		if table.expValue.CIDR.PrefixLength != ipNet.PrefixLength {
			t.Errorf("Unexpected PrefixLength in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.PrefixLength, ipNet.PrefixLength)
		}
	}
}

func TestToAntreaPeerForCRD(t *testing.T) {
	testCNPObj := &crdv1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnpA",
		},
	}
	cidr := "10.0.0.0/16"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	selectorIP := crdv1beta1.IPBlock{CIDR: cidr}
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPodsPeer := matchAllPeer
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorAll, nil, nil).NormalizedName)}
	// cgA with selector present in cache
	cgA := crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1beta1.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	tests := []struct {
		name            string
		inPeers         []crdv1beta1.NetworkPolicyPeer
		outPeer         controlplane.NetworkPolicyPeer
		direction       controlplane.Direction
		namedPortExists bool
		cgExists        bool
		clusterSetScope bool
	}{
		{
			name: "pod-ns-selector-peer-ingress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, &selectorB, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, nil, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "pod-ns-selector-peer-egress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, &selectorB, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, nil, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "ipblock-selector-peer-ingress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "ipblock-selector-peer-egress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name:      "empty-peer-ingress",
			inPeers:   []crdv1beta1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionIn,
		},
		{
			name: "peer-ingress-with-cg",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					Group: cgA.Name,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{cgA.Name},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name:            "empty-peer-egress-with-named-port",
			inPeers:         []crdv1beta1.NetworkPolicyPeer{},
			outPeer:         matchAllPodsPeer,
			direction:       controlplane.DirectionOut,
			namedPortExists: true,
		},
		{
			name:      "empty-peer-egress-without-named-port",
			inPeers:   []crdv1beta1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionOut,
		},
		{
			name: "peer-egress-with-cg",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					Group: cgA.Name,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{cgA.Name},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "node-selector-peer-ingress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					NodeSelector: &selectorA,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA).NormalizedName),
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "node-selector-peer-egress",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					NodeSelector: &selectorA,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA).NormalizedName),
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "stretched-policy-peer",
			inPeers: []crdv1beta1.NetworkPolicyPeer{
				{
					PodSelector: &selectorA,
					Scope:       crdv1beta1.ScopeClusterSet,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				LabelIdentities: []uint32{1},
				AddressGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName),
				},
			},
			direction:       controlplane.DirectionIn,
			clusterSetScope: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.addClusterGroup(&cgA)
			npc.cgStore.Add(&cgA)
			if tt.clusterSetScope {
				defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Multicluster, true)()
				labelIdentityA := "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:foo1=bar1"
				labelIdentityB := "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:foo2=bar2"
				npc.labelIdentityInterface.AddLabelIdentity(labelIdentityA, 1)
				npc.labelIdentityInterface.AddLabelIdentity(labelIdentityB, 2)
			}
			actualPeer, _, _ := npc.toAntreaPeerForCRD(tt.inPeers, testCNPObj, tt.direction, tt.namedPortExists)
			if !reflect.DeepEqual(tt.outPeer.AddressGroups, actualPeer.AddressGroups) {
				t.Errorf("Unexpected AddressGroups in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.AddressGroups, actualPeer.AddressGroups)
			}
			if !reflect.DeepEqual(tt.outPeer.LabelIdentities, actualPeer.LabelIdentities) {
				t.Errorf("Unexpected LabelIdentities in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.LabelIdentities, actualPeer.LabelIdentities)
			}
			if len(tt.outPeer.IPBlocks) != len(actualPeer.IPBlocks) {
				t.Errorf("Unexpected number of IPBlocks in Antrea Peer conversion. Expected %v, got %v", len(tt.outPeer.IPBlocks), len(actualPeer.IPBlocks))
			}
			for i := 0; i < len(tt.outPeer.IPBlocks); i++ {
				if !compareIPBlocks(&(tt.outPeer.IPBlocks[i]), &(actualPeer.IPBlocks[i])) {
					t.Errorf("Unexpected IPBlocks in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.IPBlocks[i], actualPeer.IPBlocks[i])
				}
			}
		})
	}
}

func TestCreateAppliedToGroupsForGroup(t *testing.T) {
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}
	cidr := "10.0.0.0/24"
	// cgA with selector present in cache
	clusterGroupWithSelector := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec:       crdv1beta1.GroupSpec{NamespaceSelector: &selector},
	}
	// cgB with IPBlock present in cache
	clusterGroupWithIPBlock := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec:       crdv1beta1.GroupSpec{IPBlocks: []crdv1beta1.IPBlock{{CIDR: cidr}}},
	}
	groupWithSelector := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
		Spec:       crdv1beta1.GroupSpec{PodSelector: &selector},
	}
	// gB with IPBlock present in cache
	groupWithIPBlock := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsB", Name: "gB", UID: "uidB"},
		Spec:       crdv1beta1.GroupSpec{IPBlocks: []crdv1beta1.IPBlock{{CIDR: cidr}}},
	}
	_, npc := newController(nil, nil)
	npc.addClusterGroup(clusterGroupWithSelector)
	npc.addClusterGroup(clusterGroupWithIPBlock)
	npc.addGroup(groupWithSelector)
	npc.addGroup(groupWithIPBlock)
	tests := []struct {
		name           string
		inputNamespace string
		inputGroup     string
		expectedATG    *antreatypes.AppliedToGroup
	}{
		{
			name:        "empty cluster group name",
			inputGroup:  "",
			expectedATG: nil,
		},
		{
			name:        "cluster group with IPBlock",
			inputGroup:  clusterGroupWithIPBlock.Name,
			expectedATG: nil,
		},
		{
			name:        "non-existing cluster group",
			inputGroup:  "foo",
			expectedATG: nil,
		},
		{
			name:       "cluster group with selectors",
			inputGroup: clusterGroupWithSelector.Name,
			expectedATG: &antreatypes.AppliedToGroup{
				UID:         clusterGroupWithSelector.UID,
				Name:        clusterGroupWithSelector.Name,
				SourceGroup: clusterGroupWithSelector.Name,
			},
		},
		{
			name:           "empty group name",
			inputNamespace: "default",
			inputGroup:     "",
			expectedATG:    nil,
		},
		{
			name:           "group with IPBlock",
			inputNamespace: groupWithIPBlock.Namespace,
			inputGroup:     groupWithIPBlock.Name,
			expectedATG:    nil,
		},
		{
			name:           "non-existing group",
			inputNamespace: "foo",
			inputGroup:     "bar",
			expectedATG:    nil,
		},
		{
			name:           "group with selectors",
			inputNamespace: groupWithSelector.Namespace,
			inputGroup:     groupWithSelector.Name,
			expectedATG: &antreatypes.AppliedToGroup{
				UID:         groupWithSelector.UID,
				Name:        fmt.Sprintf("%s/%s", groupWithSelector.Namespace, groupWithSelector.Name),
				SourceGroup: fmt.Sprintf("%s/%s", groupWithSelector.Namespace, groupWithSelector.Name),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualATG := npc.createAppliedToGroupForGroup(tt.inputNamespace, tt.inputGroup)
			assert.Equal(t, tt.expectedATG, actualATG, "appliedToGroup does not match")
		})
	}
}
