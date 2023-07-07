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

package networkpolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/featuregate"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
)

var (
	query       = crdv1beta1.IGMPQuery
	report      = crdv1beta1.IGMPReportV1
	allowAction = crdv1beta1.RuleActionAllow
	dropAction  = crdv1beta1.RuleActionDrop
	passAction  = crdv1beta1.RuleActionPass
	portNum80   = int32(80)
)

func TestValidateAntreaClusterNetworkPolicy(t *testing.T) {
	tests := []struct {
		name           string
		featureGates   map[featuregate.Feature]bool
		policy         *crdv1beta1.ClusterNetworkPolicy
		operation      admv1.Operation
		expectedReason string
	}{
		{
			name: "acnp-non-existent-tier",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent-tier",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "non-existent-tier",
				},
			},
			operation:      admv1.Create,
			expectedReason: "tier non-existent-tier does not exist",
		},
		{
			name: "acnp-static-tier",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-static-tier",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "NetworkOps",
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-ingress-baseline-pass-action",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-ingress-baseline-pass-action",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Baseline",
					Ingress: []crdv1beta1.Rule{
						{
							Action: &passAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`Pass` action should not be set for Baseline Tier policy rules",
		},
		{
			name: "acnp-egress-baseline-pass-action",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-egress-baseline-pass-action",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Baseline",
					Egress: []crdv1beta1.Rule{
						{
							Action: &passAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`Pass` action should not be set for Baseline Tier policy rules",
		},
		{
			name: "acnp-egress-pass-action",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-egress-pass-action",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Application",
					Egress: []crdv1beta1.Rule{
						{
							Action: &passAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-non-unique-rule-name",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-non-unique-rule-name",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							Name: "rule1",
						},
						{
							Action: &passAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo3": "bar3"},
									},
								},
							},
							Name: "rule1",
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "rules names must be unique within the policy",
		},
		{
			name: "acnp-appliedto-both-spec-rule",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-both-spec-rule",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo3": "bar3"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "appliedTo should not be set in both spec and rules",
		},
		{
			name: "acnp-no-appliedto",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-no-appliedto",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "appliedTo needs to be set in either spec or rules",
		},
		{
			name: "acnp-portion-rule-appliedto",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-portion-rule-appliedto",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar1"},
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							Name: "rule1",
						},
						{
							Action: &passAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo3": "bar3"},
									},
								},
							},
							Name: "rule2",
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "appliedTo field should either be set in all rules or in none of them",
		},
		{
			name: "acnp-rule-appliedto",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-appliedto",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar1"},
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							Name: "rule1",
						},
						{
							Action: &passAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo3": "bar3"},
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo4": "bar4"},
									},
								},
							},
							Name: "rule2",
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-appliedto-group-set-with-psel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-set-with-psel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Group: "group1",
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-group-set-with-nssel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-set-with-nssel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Group: "group1",
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-group-alone",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-alone",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Group: "group1",
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1beta1.PeerNamespaces{
										Match: crdv1beta1.NamespaceMatchSelf,
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-rule-group-set-with-psel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-psel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-nssel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-nssel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-ipblock",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-ipblock",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1beta1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-ns",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-ns",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1beta1.PeerNamespaces{
										Match: crdv1beta1.NamespaceMatchSelf,
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-fqdn",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-fqdn",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									FQDN:  "foo.bar",
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-eesel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-eesel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									ExternalEntitySelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-alone",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-alone",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									Group: "group1",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-rule-ns-set-with-nssel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-ns-set-with-nssel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
									Namespaces: &crdv1beta1.PeerNamespaces{
										Match: crdv1beta1.NamespaceMatchSelf,
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "namespaces and namespaceSelector cannot be set at the same time for a single NetworkPolicyPeer",
		},
		{
			name: "acnp-double-peer-namespace-field",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-double-peer-namespace-field",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1beta1.PeerNamespaces{
										Match:      crdv1beta1.NamespaceMatchSelf,
										SameLabels: []string{"test"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "only one matching criteria can be specified in a single peer namespaces field",
		},
		{
			name: "acnp-invalid-rule-samelabels-key",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-rule-samelabels-key",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1beta1.PeerNamespaces{
										SameLabels: []string{"&illegalKey"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Update,
			expectedReason: "Invalid label key in sameLabels rule: &illegalKey",
		},
		{
			name: "acnp-toservice-set-with-to",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-to",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							ToServices: []crdv1beta1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-set-with-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							ToServices: []crdv1beta1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-set-with-protocols",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{},
								},
							},
							ToServices: []crdv1beta1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-alone",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-alone",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							ToServices: []crdv1beta1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-invalid-fqdn",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-fqdn",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									FQDN: "foo!bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "invalid characters in egress rule fqdn field: foo!bar",
		},
		{
			name: "acnp-valid-fqdn",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-valid-fqdn",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									FQDN: "foo.bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-endport-without-port-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-endport-without-port-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									EndPort: &portNum80,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "if `endPort` is specified `port` must be specified",
		},
		{
			name: "acnp-sourceendport-without-sourceport-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-sourceendport-without-port-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									SourceEndPort: &int32For32230,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "if `sourceEndPort` is specified `sourcePort` must be specified",
		},
		{
			name: "acnp-endport-smaller-port-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-endport-smaller-port-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port:    &int81,
									EndPort: &portNum80,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`endPort` should be greater than or equal to `port`",
		},
		{
			name: "acnp-sourceendport-smaller-sourceport-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-sourceendport-smaller-port-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									SourcePort:    &int32For32230,
									SourceEndPort: &int32For32220,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "`sourceEndPort` should be greater than or equal to `sourcePort`",
		},
		{
			name: "acnp-named-port-with-endport-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-named-port-with-endport-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port:    &strHTTP,
									EndPort: &portNum80,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "if `port` is a string `endPort` cannot be specified",
		},
		{
			name: "acnp-port-range-in-ports",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-port-range-in-ports",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port:    &int80,
									EndPort: &int32For1999,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name: "acnp-invalid-label-key-applied-to",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-key-applied-to",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo=": "bar"},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "acnp-invalid-label-value-applied-to",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-value-applied-to",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo": "bar"},
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar="},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label value: bar=: a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')",
		},
		{
			name: "acnp-invalid-label-key-rule",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-key-rule",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo=": "bar1"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "acnp-appliedto-service-set-with-psel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-set-with-psel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo2",
								Name:      "bar2",
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "service cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-service-and-psel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-and-psel",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo2",
								Name:      "bar2",
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "a rule/policy cannot be applied to Services and other peers at the same time",
		},
		{
			name: "acnp-appliedto-service-with-egress-rule",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-with-egress-rule",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1beta1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "egress rule cannot be applied to Services",
		},
		{
			name: "egress-rule-appliedto-service",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-appliedto-service",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1beta1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									Service: &crdv1beta1.NamespacedName{
										Namespace: "foo1",
										Name:      "bar1",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "egress rule cannot be applied to Services",
		},
		{
			name: "acnp-appliedto-service-from-psel",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-appliedto-service",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar1"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "a rule/policy that is applied to Services can only use ipBlock to select workloads",
		},
		{
			name: "acnp-appliedto-service-valid",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-appliedto-service",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1beta1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name:         "acnp-l7protocols-used-with-allow",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: &crdv1beta1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
										Path:   "/admin",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "",
		},
		{
			name:         "acnp-l7protocols-used-with-pass",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &passAction,
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: &crdv1beta1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "layer 7 protocols only support Allow",
		},
		{
			name:         "acnp-l7protocols-HTTP-used-with-UDP",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolUDP,
								},
							},
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: &crdv1beta1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "HTTP protocol can only be used when layer 4 protocol is TCP or unset",
		},
		{
			name:         "acnp-l7protocols-HTTP-used-with-ICMP",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							Service: &crdv1beta1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{},
								},
							},
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: &crdv1beta1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "HTTP protocol can not be used with protocol IGMP or ICMP",
		},
		{
			name:         "acnp-l7protocols-used-with-toService",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: &crdv1beta1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
							ToServices: []crdv1beta1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "layer 7 protocols can not be used with toServices",
		},
		{
			name:         "L7NetworkPolicy-disabled",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: false},
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-l7protocols",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1beta1.L7Protocol{
								{
									HTTP: nil,
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "layer 7 protocols can only be used when L7NetworkPolicy is enabled",
		},
		{
			name: "igmp-icmp-both-specified",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{
										ICMPType: &icmpType8,
										ICMPCode: &icmpCode0,
									},
									IGMP: &crdv1beta1.IGMPProtocol{
										IGMPType:     &query,
										GroupAddress: "224.0.0.1",
									},
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "protocol IGMP can not be used with other protocols or other properties like from, to",
		},
		{
			name: "only-icmp-specified",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Ingress: []crdv1beta1.Rule{
						{
							Name: "ingressType8",
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{
										ICMPType: &icmpType8,
										ICMPCode: &icmpCode0,
									},
								},
							},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Name: "egressWithICMP",
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{},
								},
							},
						},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "icmp-specified-and-action-set-to-pass",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									IGMP: &crdv1beta1.IGMPProtocol{
										IGMPType:     &report,
										GroupAddress: "225.1.2.3",
									},
								},
							},
							Action: &passAction,
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "protocol IGMP does not support Pass or Reject",
		},
		// Update use same validate function as create. Only provide one update case here.
		{
			name: "acnp-non-existent-tier",
			policy: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent-tier",
				},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "non-existent-tier",
				},
			},
			operation:      admv1.Update,
			expectedReason: "tier non-existent-tier does not exist",
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for feature, value := range tt.featureGates {
				defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, feature, value)()
			}
			_, controller := newController(nil, nil)
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateAntreaPolicy(tt.policy, "", tt.operation, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}

// Antrea NetworkPolicy use the same validator and has fewer cases to validate than
// Antrea ClusterNetworkPolicy. Only provide one test case for create and update here.
func TestValidateAntreaNetworkPolicy(t *testing.T) {
	tests := []struct {
		name           string
		featureGates   map[featuregate.Feature]bool
		policy         *crdv1beta1.NetworkPolicy
		operation      admv1.Operation
		expectedReason string
	}{
		{
			name: "annp-non-existent-tier",
			policy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "non-existent-tier",
					Namespace: "x",
				},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "non-existent-tier",
				},
			},
			operation:      admv1.Create,
			expectedReason: "tier non-existent-tier does not exist",
		},
		{
			name: "annp-non-existent-tier",
			policy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "non-existent-tier",
					Namespace: "x",
				},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "non-existent-tier",
				},
			},
			operation:      admv1.Update,
			expectedReason: "tier non-existent-tier does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for feature, value := range tt.featureGates {
				defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, feature, value)()
			}
			_, controller := newController(nil, nil)
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateAntreaPolicy(tt.policy, "", tt.operation, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}

func TestValidateAntreaClusterGroup(t *testing.T) {
	tests := []struct {
		name           string
		curCG          *crdv1beta1.ClusterGroup
		oldCG          *crdv1beta1.ClusterGroup
		existGroup     *crdv1beta1.ClusterGroup
		operation      admv1.Operation
		expectedReason string
	}{
		{
			name: "cg-invalid-label-key",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-invalid-label-key",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo=": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "cg-invalid-label-value",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-invalid-label-value",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar="},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label value: bar=: a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')",
		},
		{
			name: "cg-three-fields-set",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-three-fields-set",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup",
		},
		{
			name: "cg-set-with-psel-and-nssel",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-podselector-and-namespaceselector",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "cg-set-with-nssel-and-eesel",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "annp-group-set-with-podselector-and-namespaceselector",
				},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "cg-set-with-psel-and-eesel",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-podselector-and-namespaceselector",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup",
		},
		{
			name: "cg-set-with-podselector-and-ipblock",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-podselector-and-ipblock",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup",
		},
		{
			name: "cg-set-with-ipblock",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-ipblock",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "cg-set-with-multicast",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-ipblock",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "224.0.0.0/24"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "cg-set-with-multicast-and-unicast",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-set-with-ipblock",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "224.0.0.0/24"},
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "can not set multicast groupAddress together with unicast ip address",
		},
		{
			name: "cg-with-childGroup",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-with-childGroup",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA", "cgB"},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "already-child-to-be-parent",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "already-child-to-be-parent",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"},
				},
			},
			existGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgParent",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"already-child-to-be-parent"},
				},
			},
			operation:      admv1.Create,
			expectedReason: "cannot set childGroups for ClusterGroup already-child-to-be-parent, who has 1 parents",
		},
		{
			name: "to-be-parent-of-parent",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "to-be-parent-of-parent",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgParent"},
				},
			},
			existGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgParent",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"},
				},
			},
			operation:      admv1.Create,
			expectedReason: "cannot set ClusterGroup cgParent as childGroup, who has 1 childGroups itself",
		},
		// Update using the same func as creation. Only put one case here.
		{
			name: "cg-update",
			curCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-update",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			oldCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-update",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Update,
		},
		{
			name: "cg-to-delete",
			oldCG: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-to-delete",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Delete,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, controller := newController(nil, nil)
			if tt.existGroup != nil {
				controller.cgStore.Add(tt.existGroup)
				controller.addClusterGroup(tt.existGroup)
			}
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateAntreaGroup(tt.curCG, tt.oldCG, tt.operation, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}

func TestValidateAntreaGroup(t *testing.T) {
	tests := []struct {
		name           string
		curGroup       *crdv1beta1.Group
		oldGroup       *crdv1beta1.Group
		existGroup     *crdv1beta1.Group
		operation      admv1.Operation
		expectedReason string
	}{
		{
			name: "annp-group-three-fields-set",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-three-fields-set",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlocks or childGroups can be set for a Group",
		},
		{
			name: "annp-group-set-with-psel-and-nssel",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-podselector-and-namespaceselector",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "annp-group-set-with-nssel-and-eesel",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-podselector-and-namespaceselector",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "annp-group-set-with-psel-and-eesel",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-podselector-and-namespaceselector",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					ExternalEntitySelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlocks or childGroups can be set for a Group",
		},
		{
			name: "annp-group-set-with-podselector-and-ipblock",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-podselector-and-ipblock",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlocks or childGroups can be set for a Group",
		},
		{
			name: "annp-group-set-with-ipblock",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-ipblock",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "annp-group-set-with-invalid-psel",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-set-with-invalid-psel",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo=": "bar"},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "annp-group-with-childGroup",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-with-childGroup",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA", "cgB"},
				},
			},
			operation: admv1.Create,
		},
		{
			name: "already-child-to-be-parent",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "already-child-to-be-parent",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"},
				},
			},
			existGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cgParent",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"already-child-to-be-parent"},
				},
			},
			operation:      admv1.Create,
			expectedReason: "cannot set childGroups for Group x/already-child-to-be-parent, who has 1 parents",
		},
		{
			name: "to-be-parent-of-parent",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "to-be-parent-of-parent",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgParent"},
				},
			},
			existGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cgParent",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"},
				},
			},
			operation:      admv1.Create,
			expectedReason: "cannot set Group x/cgParent as childGroup, who has 1 childGroups itself",
		},
		// Update using the same func as creation. Only put one case here.
		{
			name: "annp-group-update",
			curGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-update",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			oldGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-update",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Update,
		},
		{
			name: "annp-group-to-delete",
			oldGroup: &crdv1beta1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "annp-group-to-delete",
					Namespace: "x",
				},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
			operation: admv1.Delete,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, controller := newController(nil, nil)
			if tt.existGroup != nil {
				controller.gStore.Add(tt.existGroup)
				controller.addGroup(tt.existGroup)
			}
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateAntreaGroup(tt.curGroup, tt.oldGroup, tt.operation, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}

func TestValidateTier(t *testing.T) {
	tests := []struct {
		name           string
		curTier        *crdv1beta1.Tier
		oldTier        *crdv1beta1.Tier
		existTierNum   int
		existACNP      *crdv1beta1.ClusterNetworkPolicy
		existANNP      *crdv1beta1.NetworkPolicy
		operation      admv1.Operation
		user           authenticationv1.UserInfo
		expectedReason string
	}{
		{
			name: "create-tier-pass",
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 3,
				},
			},
			operation: admv1.Create,
			user: authenticationv1.UserInfo{
				Username: "default",
			},
		},
		{
			name: "create-tier-failed-with-reserved-priority",
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-251",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 251,
				},
			},
			operation: admv1.Create,
			user: authenticationv1.UserInfo{
				Username: "default",
			},
			expectedReason: "tier tier-priority-251 priority 251 is reserved",
		},
		{
			name: "over-max-tier",
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: int32(maxSupportedTiers) + 1,
				},
			},
			existTierNum:   maxSupportedTiers,
			operation:      admv1.Create,
			expectedReason: fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers),
		},
		{
			name: "overlap-tier",
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-1",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 1,
				},
			},
			existTierNum:   1,
			operation:      admv1.Create,
			expectedReason: "tier tier-priority-1 priority 1 overlaps with existing Tier",
		},
		{
			name: "update-tier-not-allowed",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 3,
				},
			},
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 5,
				},
			},
			operation: admv1.Update,
			user: authenticationv1.UserInfo{
				Username: "default",
			},
			expectedReason: "update to Tier priority is not allowed",
		},
		{
			name: "update-tier-allowed",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 3,
				},
			},
			curTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 5,
				},
			},
			operation: admv1.Update,
			user: authenticationv1.UserInfo{
				Username: "system:serviceaccount:kube-system:antrea-controller",
			},
		},
		{
			name: "delete-tier-pass",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-priority-3",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 3,
				},
			},
			operation: admv1.Delete,
			user: authenticationv1.UserInfo{
				Username: "default",
			},
		},
		{
			name: "delete-reserved-tier",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "baseline",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 3,
				},
			},
			operation: admv1.Delete,
			user: authenticationv1.UserInfo{
				Username: "default",
			},
			expectedReason: "cannot delete reserved tier baseline",
		},
		{
			name: "delete-annp-ref-tier",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-annp-ref",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 0,
				},
			},
			existANNP: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: crdv1beta1.NetworkPolicySpec{
					Tier: "tier-annp-ref",
				},
			},
			operation:      admv1.Delete,
			expectedReason: "tier tier-annp-ref is referenced by 1 Antrea NetworkPolicies",
		},
		{
			name: "delete-acnp-ref-tier",
			oldTier: &crdv1beta1.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-acnp-ref",
				},
				Spec: crdv1beta1.TierSpec{
					Priority: 0,
				},
			},
			existACNP: &crdv1beta1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "npA", UID: "uidA"},
				Spec: crdv1beta1.ClusterNetworkPolicySpec{
					Tier: "tier-acnp-ref",
				},
			},
			operation:      admv1.Delete,
			expectedReason: "tier tier-acnp-ref is referenced by 1 Antrea ClusterNetworkPolicies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, controller := newController(nil, nil)
			for i := 1; i <= tt.existTierNum; i++ {
				controller.tierStore.Add(&crdv1beta1.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("tier-priority-%d", i),
					},
					Spec: crdv1beta1.TierSpec{
						Priority: int32(i),
					},
				})
			}
			if tt.existACNP != nil {
				controller.acnpStore.Add(tt.existACNP)
			}
			if tt.existANNP != nil {
				controller.annpStore.Add(tt.existANNP)
			}
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateTier(tt.curTier, tt.oldTier, tt.operation, tt.user)
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}

func TestValidateAdminNetworkPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policy         metav1.Object
		operation      admv1.Operation
		expectedReason string
	}{
		{
			name: "anp-has-same-labels-rule",
			policy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										SameLabels: []string{"labelA"},
									},
								},
							},
						},
					},
					Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
		{
			name: "anp-update-to-same-labels-rule",
			policy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										SameLabels: []string{"labelA"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Update,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
		{
			name: "anp-has-not-same-labels-rule",
			policy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										NotSameLabels: []string{"labelA", "labelB"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
		{
			name: "banp-has-same-labels-rule",
			policy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										SameLabels: []string{"labelA"},
									},
								},
							},
						},
					},
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
		{
			name: "banp-update-to-same-labels-rule",
			policy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										SameLabels: []string{"labelA"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Update,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
		{
			name: "banp-has-not-same-labels-rule",
			policy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										NotSameLabels: []string{"labelA", "labelB"},
									},
								},
							},
						},
					},
				},
			},
			operation:      admv1.Create,
			expectedReason: "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, controller := newController(nil, nil)
			validator := NewNetworkPolicyValidator(controller.NetworkPolicyController)
			actualReason, allowed := validator.validateAdminNetworkPolicy(tt.policy, "", tt.operation, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}
