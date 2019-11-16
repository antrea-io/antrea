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

package networkpolicy

import (
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestToGroupSelector(t *testing.T) {
	pSelector := metav1.LabelSelector{}
	nSelector := metav1.LabelSelector{}
	tables := []struct {
		namespace        string
		podSelector      *metav1.LabelSelector
		nsSelector       *metav1.LabelSelector
		expGroupSelector *antreatypes.GroupSelector
	}{
		{
			"nsName",
			&pSelector,
			nil,
			&antreatypes.GroupSelector{
				Namespace:         "nsName",
				NamespaceSelector: nil,
				PodSelector:       &pSelector,
				NormalizedName:    generateNormalizedName("nsName", &pSelector, nil),
			},
		},
		{
			"nsName",
			nil,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       nil,
				NormalizedName:    generateNormalizedName("", nil, &nSelector),
			},
		},
		{
			"",
			nil,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       nil,
				NormalizedName:    generateNormalizedName("", nil, &nSelector),
			},
		},
		{
			"nsName",
			&pSelector,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       &pSelector,
				NormalizedName:    generateNormalizedName("", &pSelector, &nSelector),
			},
		},
	}
	for _, table := range tables {
		group := toGroupSelector(table.namespace, table.podSelector, table.nsSelector)
		if group.Namespace != table.expGroupSelector.Namespace {
			t.Errorf("Group Namespace incorrectly set. Expected %s, got: %s", table.expGroupSelector.Namespace, group.Namespace)
		}
		if group.NormalizedName != table.expGroupSelector.NormalizedName {
			t.Errorf("Group normalized Name incorrectly set. Expected %s, got: %s", table.expGroupSelector.NormalizedName, group.NormalizedName)
		}
		if group.NamespaceSelector != table.expGroupSelector.NamespaceSelector {
			t.Errorf("Group NamespaceSelector incorrectly set. Expected %v, got: %v", table.expGroupSelector.NamespaceSelector, group.NamespaceSelector)
		}
		if group.PodSelector != table.expGroupSelector.PodSelector {
			t.Errorf("Group PodSelector incorrectly set. Expected %v, got: %v", table.expGroupSelector.PodSelector, group.PodSelector)
		}
	}
}

func TestNormalizeExpr(t *testing.T) {
	tables := []struct {
		key     string
		op      metav1.LabelSelectorOperator
		values  []string
		expName string
	}{
		{
			"role",
			metav1.LabelSelectorOpIn,
			[]string{"db", "app"},
			fmt.Sprintf("%s %s %s", "role", metav1.LabelSelectorOpIn, []string{"db", "app"}),
		},
		{
			"role",
			metav1.LabelSelectorOpExists,
			[]string{},
			fmt.Sprintf("%s %s", "role", metav1.LabelSelectorOpExists),
		},
	}
	for _, table := range tables {
		name := normalizeExpr(table.key, table.op, table.values)
		if name != table.expName {
			t.Errorf("Name not normalized correctly. Expected %s, got %s", table.expName, name)
		}
	}
}

func TestGenerateNormalizedName(t *testing.T) {
	pLabels := map[string]string{"user": "dev"}
	req1 := metav1.LabelSelectorRequirement{
		Key:      "role",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"db", "app"},
	}
	pExprs := []metav1.LabelSelectorRequirement{req1}
	normalizedPodSelector := "role In [db app] And user In [dev]"
	nLabels := map[string]string{"scope": "test"}
	req2 := metav1.LabelSelectorRequirement{
		Key:      "env",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"staging", "prod"},
	}
	nExprs := []metav1.LabelSelectorRequirement{req2}
	pSelector := metav1.LabelSelector{
		MatchLabels:      pLabels,
		MatchExpressions: pExprs,
	}
	nSelector := metav1.LabelSelector{
		MatchLabels:      nLabels,
		MatchExpressions: nExprs,
	}
	normalizedNSSelector := "env NotIn [staging prod] And scope In [test]"
	tables := []struct {
		namespace string
		pSelector *metav1.LabelSelector
		nSelector *metav1.LabelSelector
		expName   string
	}{
		{
			"nsName",
			&pSelector,
			nil,
			fmt.Sprintf("namespace=nsName And podSelector=%s", normalizedPodSelector),
		},
		{
			"nsName",
			nil,
			nil,
			"namespace=nsName",
		},
		{
			"nsName",
			nil,
			&nSelector,
			fmt.Sprintf("namespaceSelector=%s", normalizedNSSelector),
		},
		{
			"nsName",
			&pSelector,
			&nSelector,
			fmt.Sprintf("namespaceSelector=%s And podSelector=%s", normalizedNSSelector, normalizedPodSelector),
		},
	}
	for _, table := range tables {
		name := generateNormalizedName(table.namespace, table.pSelector, table.nSelector)
		if table.expName != name {
			t.Errorf("Unexpected normalized name. Expected %s, got %s", table.expName, name)
		}
	}
}

func TestToAntreaProtocol(t *testing.T) {
	udpProto := v1.ProtocolUDP
	tcpProto := v1.ProtocolTCP
	sctpProto := v1.ProtocolSCTP
	tables := []struct {
		proto            *v1.Protocol
		expInternalProto networkpolicy.Protocol
	}{
		{nil, networkpolicy.ProtocolTCP},
		{&udpProto, networkpolicy.ProtocolUDP},
		{&tcpProto, networkpolicy.ProtocolTCP},
		{&sctpProto, networkpolicy.ProtocolSCTP},
	}
	for _, table := range tables {
		protocol := toAntreaProtocol(table.proto)
		if *protocol != table.expInternalProto {
			t.Errorf("Unexpected Antrea protocol. Expected %v, got %v", table.expInternalProto, *protocol)
		}
	}
}

func TestToAntreaServices(t *testing.T) {
	tcpProto := v1.ProtocolTCP
	portNum := int32(80)
	tables := []struct {
		ports     []networkingv1.NetworkPolicyPort
		expValues []networkpolicy.Service
	}{
		{
			getK8sNetworkPolicyPorts(tcpProto),
			[]networkpolicy.Service{
				{
					Protocol: toAntreaProtocol(&tcpProto),
					Port:     &portNum,
				},
			},
		},
	}
	for _, table := range tables {
		services := toAntreaServices(table.ports)
		service := services[0]
		expValue := table.expValues[0]
		if *service.Protocol != *expValue.Protocol {
			t.Errorf("Unexpected Antrea Protocol in Antrea Service. Expected %v, got %v", *expValue.Protocol, *service.Protocol)
		}
		if *service.Port != *expValue.Port {
			t.Errorf("Unexpected Antrea Port in Antrea Service. Expected %v, got %v", *expValue.Port, *service.Port)
		}
	}
}

func getK8sNetworkPolicyPorts(proto v1.Protocol) []networkingv1.NetworkPolicyPort {
	portNum := intstr.FromInt(80)
	port := networkingv1.NetworkPolicyPort{
		Protocol: &proto,
		Port:     &portNum,
	}
	ports := []networkingv1.NetworkPolicyPort{port}
	return ports
}
