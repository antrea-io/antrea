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
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/featuregate"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	"antrea.io/antrea/pkg/features"
)

func TestValidateAntreaPolicy(t *testing.T) {
	allowAction := crdv1alpha1.RuleActionAllow
	passAction := crdv1alpha1.RuleActionPass
	int32For80 := int32(80)

	tests := []struct {
		name           string
		featureGates   map[featuregate.Feature]bool
		policy         *crdv1alpha1.ClusterNetworkPolicy
		expectedReason string
	}{
		{
			name: "acnp-non-existent-tier",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent-tier",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "non-existent-tier",
				},
			},
			expectedReason: "tier non-existent-tier does not exist",
		},
		{
			name: "acnp-static-tier",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-static-tier",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Tier: "NetworkOps",
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-ingress-baseline-pass-action",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-ingress-baseline-pass-action",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Baseline",
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &passAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "`Pass` action should not be set for Baseline Tier policy rules",
		},
		{
			name: "acnp-egress-baseline-pass-action",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-egress-baseline-pass-action",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Baseline",
					Egress: []crdv1alpha1.Rule{
						{
							Action: &passAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "`Pass` action should not be set for Baseline Tier policy rules",
		},
		{
			name: "acnp-egress-pass-action",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-egress-pass-action",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Tier: "Application",
					Egress: []crdv1alpha1.Rule{
						{
							Action: &passAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "",
		},
		{
			name: "acnp-non-unique-rule-name",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-non-unique-rule-name",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "rules names must be unique within the policy",
		},
		{
			name: "acnp-appliedto-both-spec-rule",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-both-spec-rule",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
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
			expectedReason: "appliedTo should not be set in both spec and rules",
		},
		{
			name: "acnp-no-appliedto",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-no-appliedto",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "appliedTo needs to be set in either spec or rules",
		},
		{
			name: "acnp-portion-rule-appliedto",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-portion-rule-appliedto",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar1"},
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
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
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "appliedTo field should either be set in all rules or in none of them",
		},
		{
			name: "acnp-rule-appliedto",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-appliedto",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo1": "bar1"},
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
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
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo3": "bar3"},
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
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
			expectedReason: "",
		},
		{
			name: "acnp-appliedto-group-set-with-psel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-set-with-psel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Group: "group1",
						},
					},
				},
			},
			expectedReason: "group cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-group-set-with-nssel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-set-with-nssel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Group: "group1",
						},
					},
				},
			},
			expectedReason: "group cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-group-alone",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-group-alone",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Group: "group1",
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-rule-group-set-with-psel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-psel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-nssel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-nssel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-ipblock",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-ipblock",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1alpha1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-ns",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-ns",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
									Group: "group1",
								},
							},
						},
					},
				},
			},
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-fqdn",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-fqdn",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									FQDN:  "foo.bar",
									Group: "group1",
								},
							},
						},
					},
				},
			},
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-set-with-eesel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-set-with-eesel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "group cannot be set with other peers in rules",
		},
		{
			name: "acnp-rule-group-alone",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-group-alone",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Group: "group1",
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-rule-ns-set-with-nssel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-rule-ns-set-with-nssel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "namespaces and namespaceSelector cannot be set at the same time for a single NetworkPolicyPeer",
		},
		{
			name: "acnp-toservice-set-with-to",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-to",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo2": "bar2"},
									},
								},
							},
							ToServices: []crdv1alpha1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-set-with-ports",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-ports",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							ToServices: []crdv1alpha1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-set-with-protocols",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-set-with-protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1alpha1.ICMPProtocol{},
								},
							},
							ToServices: []crdv1alpha1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "`toServices` cannot be used with `to`, `ports` or `protocols`",
		},
		{
			name: "acnp-toservice-alone",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-toservice-alone",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							ToServices: []crdv1alpha1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-invalid-fqdn",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-fqdn",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									FQDN: "foo!bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "invalid characters in egress rule fqdn field: foo!bar",
		},
		{
			name: "acnp-valid-fqdn",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-valid-fqdn",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									FQDN: "foo.bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-endport-without-port-in-ports",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-endport-without-port-in-ports",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									EndPort: &int32For80,
								},
							},
						},
					},
				},
			},
			expectedReason: "if `endPort` is specified `port` must be specified",
		},
		{
			name: "acnp-endport-smaller-port-in-ports",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-endport-smaller-port-in-ports",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port:    &int81,
									EndPort: &int32For80,
								},
							},
						},
					},
				},
			},
			expectedReason: "`endPort` should be greater than or equal to `port`",
		},
		{
			name: "acnp-named-port-with-endport-in-ports",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-named-port-with-endport-in-ports",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port:    &strHTTP,
									EndPort: &int32For80,
								},
							},
						},
					},
				},
			},
			expectedReason: "if `port` is a string `endPort` cannot be specified",
		},
		{
			name: "acnp-port-range-in-ports",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-port-range-in-ports",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port:    &int80,
									EndPort: &int32For1999,
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name: "acnp-invalid-label-key-applied-to",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-key-applied-to",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo=": "bar"},
							},
						},
					},
				},
			},
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "acnp-invalid-label-value-applied-to",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-value-applied-to",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"foo": "bar"},
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
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
			expectedReason: "Invalid label value: bar=: a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')",
		},
		{
			name: "acnp-invalid-label-key-rule",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-invalid-label-key-rule",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "acnp-appliedto-service-set-with-psel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-set-with-psel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo2",
								Name:      "bar2",
							},
						},
					},
				},
			},
			expectedReason: "service cannot be set with other peers in appliedTo",
		},
		{
			name: "acnp-appliedto-service-and-psel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-and-psel",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo2",
								Name:      "bar2",
							},
						},
					},
				},
			},
			expectedReason: "a rule/policy cannot be applied to Services and other peers at the same time",
		},
		{
			name: "acnp-appliedto-service-with-egress-rule",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-appliedto-service-with-egress-rule",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1alpha1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "egress rule cannot be applied to Services",
		},
		{
			name: "egress-rule-appliedto-service",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-appliedto-service",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1alpha1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
							AppliedTo: []crdv1alpha1.AppliedTo{
								{
									Service: &crdv1alpha1.NamespacedName{
										Namespace: "foo1",
										Name:      "bar1",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "egress rule cannot be applied to Services",
		},
		{
			name: "acnp-appliedto-service-from-psel",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-appliedto-service",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
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
			expectedReason: "a rule/policy that is applied to Services can only use ipBlock to select workloads",
		},
		{
			name: "acnp-appliedto-service-valid",
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-appliedto-service",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1alpha1.IPBlock{
										CIDR: "10.0.0.10/32",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "",
		},
		{
			name:         "acnp-l7protocols-used-with-allow",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: &crdv1alpha1.HTTPProtocol{
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
			expectedReason: "",
		},
		{
			name:         "acnp-l7protocols-used-with-pass",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &passAction,
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: &crdv1alpha1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "layer 7 protocols only support Allow",
		},
		{
			name:         "acnp-l7protocols-HTTP-used-with-UDP",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolUDP,
								},
							},
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: &crdv1alpha1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "HTTP protocol can only be used when layer 4 protocol is TCP or unset",
		},
		{
			name:         "acnp-l7protocols-HTTP-used-with-ICMP",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ingress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							Service: &crdv1alpha1.NamespacedName{
								Namespace: "foo1",
								Name:      "bar1",
							},
						},
					},
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1alpha1.ICMPProtocol{},
								},
							},
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: &crdv1alpha1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
						},
					},
				},
			},
			expectedReason: "HTTP protocol can not be used with protocol IGMP or ICMP",
		},
		{
			name:         "acnp-l7protocols-used-with-toService",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: true},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo1": "bar1"},
							},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: &crdv1alpha1.HTTPProtocol{
										Host:   "test.com",
										Method: "GET",
									},
								},
							},
							ToServices: []crdv1alpha1.PeerService{
								{
									Name:      "foo",
									Namespace: "bar",
								},
							},
						},
					},
				},
			},
			expectedReason: "layer 7 protocols can not be used with toServices",
		},
		{
			name:         "L7NetworkPolicy-disabled",
			featureGates: map[featuregate.Feature]bool{features.L7NetworkPolicy: false},
			policy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-rule-l7protocols",
				},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Action: &allowAction,
							L7Protocols: []crdv1alpha1.L7Protocol{
								{
									HTTP: nil,
								},
							},
						},
					},
				},
			},
			expectedReason: "layer 7 protocols can only be used when L7NetworkPolicy is enabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for feature, value := range tt.featureGates {
				defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, feature, value)()
			}

			_, c := newController()
			v := NewNetworkPolicyValidator(c.NetworkPolicyController)
			actualReason, allowed := v.validateAntreaPolicy(tt.policy, nil, admv1.Create, authenticationv1.UserInfo{})
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
		group          *crdv1alpha2.ClusterGroup
		expectedReason string
	}{
		{
			name: "cg-invalid-label-key",
			group: &crdv1alpha2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-invalid-label-key",
				},
				Spec: crdv1alpha2.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo=": "bar"},
					},
				},
			},
			expectedReason: "Invalid label key: foo=: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "cg-invalid-label-value",
			group: &crdv1alpha2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cg-invalid-label-value",
				},
				Spec: crdv1alpha2.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar="},
					},
				},
			},
			expectedReason: "Invalid label value: bar=: a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			v := NewNetworkPolicyValidator(c.NetworkPolicyController)
			actualReason, allowed := v.validateAntreaGroup(tt.group, nil, admv1.Create, authenticationv1.UserInfo{})
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
		group          *crdv1alpha3.Group
		expectedReason string
	}{
		{
			name: "anp-group-set-with-podselector-and-ipblock",
			group: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "anp-group-set-with-podselector-and-ipblock",
					Namespace: "x",
				},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo=": "bar"},
					},
					IPBlocks: []crdv1alpha1.IPBlock{
						{CIDR: "10.0.0.10/32"},
					},
				},
			},
			expectedReason: "At most one of podSelector, externalEntitySelector, serviceReference, ipBlocks or childGroups can be set for a Group",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			v := NewNetworkPolicyValidator(c.NetworkPolicyController)
			actualReason, allowed := v.validateAntreaGroup(tt.group, nil, admv1.Create, authenticationv1.UserInfo{})
			assert.Equal(t, tt.expectedReason, actualReason)
			if tt.expectedReason == "" {
				assert.True(t, allowed)
			} else {
				assert.False(t, allowed)
			}
		})
	}
}
