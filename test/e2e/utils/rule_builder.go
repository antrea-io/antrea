// Copyright 2025 Antrea Authors
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

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

type RuleBuilder struct {
	Protoc               AntreaPolicyProtocol
	Port                 *int32
	PortName             *string
	EndPort              *int32
	IcmpType             *int32
	IcmpCode             *int32
	IgmpType             *int32
	GroupAddress         *string
	PodSelector          map[string]string
	NsSelector           map[string]string
	PodSelectorMatchExp  []metav1.LabelSelectorRequirement
	NodeSelectorMatchExp []metav1.LabelSelectorRequirement
	Action               crdv1beta1.RuleAction
	Name                 string
	SelfNS               bool
	SrcPort              *int32
	SrcEndPort           *int32

	// CNP only
	IpBlock            *crdv1beta1.IPBlock
	NodeSelector       map[string]string
	NsSelectorMatchExp []metav1.LabelSelectorRequirement
	Namespaces         *crdv1beta1.PeerNamespaces
	RuleAppliedToSpecs []ACNPAppliedToSpec
	ServiceAccount     *crdv1beta1.NamespacedName
	RuleClusterGroup   string

	// ANP only
	L7Protocols           []crdv1beta1.L7Protocol
	RuleGroup             string
	Cidr                  *string
	EeSelector            map[string]string
	EeSelectorMatchExp    []metav1.LabelSelectorRequirement
	ANPRuleAppliedToSpecs []ANNPAppliedToSpec
}

func (rb RuleBuilder) generatePodSelector() (podSel *metav1.LabelSelector) {
	if rb.PodSelector != nil || rb.PodSelectorMatchExp != nil {
		podSel = &metav1.LabelSelector{
			MatchLabels:      rb.PodSelector,
			MatchExpressions: rb.PodSelectorMatchExp,
		}
	}
	return podSel
}

func (rb RuleBuilder) generateNsSelector() (nsSel *metav1.LabelSelector) {
	if rb.NsSelector != nil || rb.NsSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      rb.NsSelector,
			MatchExpressions: rb.NsSelectorMatchExp,
		}
	}
	return nsSel
}
