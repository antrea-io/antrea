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

package stats

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/features"
)

var (
	np1 = &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar", UID: "uid1"},
	}
	np2 = &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "baz", UID: "uid2"},
	}
	cnp1 = &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "bar", UID: "uid3"},
	}
	cnp2 = &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "baz", UID: "uid4"},
	}
	anp1 = &crdv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar", UID: "uid5"},
	}
	anp2 = &crdv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "baz", UID: "uid6"},
	}
)

// runWrapper wraps the Run method of the Aggregator and is used to avoid race conditions in tests.
// It waits for the Aggregator to register all test policies (waits until Add event handlers have
// been called for all test policies) before starting the Run method in a goroutine. It then
// collects all the provided summaries. Finally it ensures that all the summaries have been
// processed to completion by Run, before returning.
// This method is not meant to be called in a goroutine, and will block until processing is
// completed.
func runWrapper(t *testing.T, a *Aggregator, policyCount int, summaries []*controlplane.NodeStatsSummary) {
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	err := wait.PollImmediate(100*time.Millisecond, time.Second, func() (done bool, err error) {
		count := len(a.ListNetworkPolicyStats("")) + len(a.ListAntreaNetworkPolicyStats("")) + len(a.ListAntreaClusterNetworkPolicyStats())
		return (count >= policyCount), nil
	})
	require.NoError(t, err, "Timeout while waiting for Add events to be processed by Aggregator")
	go func() {
		defer close(doneCh)
		a.Run(stopCh)
	}()
	for _, summary := range summaries {
		a.Collect(summary)
	}
	// Wait for all summaries to be consumed.
	err = wait.PollImmediate(100*time.Millisecond, time.Second, func() (done bool, err error) {
		return len(a.dataCh) == 0, nil
	})
	require.NoError(t, err, "Timeout while waiting for summaries to be consummed by Aggregator")
	close(stopCh)
	<-doneCh
}

func TestAggregatorCollectListGet(t *testing.T) {
	tests := []struct {
		name                                    string
		summaries                               []*controlplane.NodeStatsSummary
		existingNetworkPolicies                 []runtime.Object
		existingAntreaClusterNetworkPolicies    []runtime.Object
		existingAntreaNetworkPolicies           []runtime.Object
		expectedNetworkPolicyStats              []statsv1alpha1.NetworkPolicyStats
		expectedAntreaClusterNetworkPolicyStats []statsv1alpha1.AntreaClusterNetworkPolicyStats
		expectedAntreaNetworkPolicyStats        []statsv1alpha1.AntreaNetworkPolicyStats
	}{
		{
			name: "multiple Nodes, multiple Policies",
			summaries: []*controlplane.NodeStatsSummary{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					NetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: np1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    10,
								Packets:  1,
								Sessions: 1,
							},
						},
					},
					AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule1",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    20,
										Packets:  5,
										Sessions: 2,
									},
								},
								{
									Name: "rule3",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    22,
										Packets:  52,
										Sessions: 22,
									},
								},
							},
						},
					},
					AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule2",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    20,
										Packets:  5,
										Sessions: 2,
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
					},
					NetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: np1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    20,
								Packets:  10,
								Sessions: 3,
							},
						},
					},
					AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule3",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    20,
										Packets:  8,
										Sessions: 5,
									},
								},
							},
						},
					},
					AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule4",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    100,
										Packets:  10,
										Sessions: 5,
									},
								},
							},
						},
					},
				},
			},
			existingNetworkPolicies:              []runtime.Object{np1, np2},
			existingAntreaClusterNetworkPolicies: []runtime.Object{cnp1, cnp2},
			existingAntreaNetworkPolicies:        []runtime.Object{anp1, anp2},
			expectedNetworkPolicyStats: []statsv1alpha1.NetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: np1.Namespace,
						Name:      np1.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    30,
						Packets:  11,
						Sessions: 4,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: np2.Namespace,
						Name:      np2.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
			},
			expectedAntreaClusterNetworkPolicyStats: []statsv1alpha1.AntreaClusterNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: cnp1.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    62,
						Packets:  65,
						Sessions: 29,
					},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    20,
								Packets:  5,
								Sessions: 2,
							},
						},
						{
							Name: "rule3",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    42,
								Packets:  60,
								Sessions: 27,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: cnp2.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
					RuleTrafficStats: nil,
				},
			},
			expectedAntreaNetworkPolicyStats: []statsv1alpha1.AntreaNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: anp1.Namespace,
						Name:      anp1.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    120,
						Packets:  15,
						Sessions: 7,
					},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    20,
								Packets:  5,
								Sessions: 2,
							},
						},
						{
							Name: "rule4",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    100,
								Packets:  10,
								Sessions: 5,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: anp2.Namespace,
						Name:      anp2.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
			},
		},
		{
			name: "non existing Policies",
			summaries: []*controlplane.NodeStatsSummary{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					NetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: np1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    10,
								Packets:  1,
								Sessions: 1,
							},
						},
					},
					AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule5",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    20,
										Packets:  8,
										Sessions: 5,
									},
								},
							},
						},
					},
					AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
							RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
								{
									Name: "rule6",
									TrafficStats: statsv1alpha1.TrafficStats{
										Bytes:    20,
										Packets:  8,
										Sessions: 5,
									},
								},
							},
						},
					},
				},
			},
			existingNetworkPolicies:              []runtime.Object{np2},
			existingAntreaClusterNetworkPolicies: []runtime.Object{cnp2},
			existingAntreaNetworkPolicies:        []runtime.Object{anp2},
			expectedNetworkPolicyStats: []statsv1alpha1.NetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      np2.Name,
						Namespace: np2.Namespace,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
			},
			expectedAntreaClusterNetworkPolicyStats: []statsv1alpha1.AntreaClusterNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: cnp2.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
			},
			expectedAntreaNetworkPolicyStats: []statsv1alpha1.AntreaNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      anp2.Name,
						Namespace: anp2.Namespace,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
			},
		},
		{
			name: "support old style traffic stats collection",
			summaries: []*controlplane.NodeStatsSummary{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					NetworkPolicies: []controlplane.NetworkPolicyStats{},
					AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    20,
								Packets:  8,
								Sessions: 5,
							},
						},
					},
					AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    20,
								Packets:  8,
								Sessions: 5,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
					},
					NetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: np2.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    10,
								Packets:  8,
								Sessions: 5,
							},
						},
					},
					AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    10,
								Packets:  8,
								Sessions: 5,
							},
						},
					},
					AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
						{
							NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    30,
								Packets:  3,
								Sessions: 5,
							},
						},
					},
				},
			},
			existingNetworkPolicies:              []runtime.Object{np2},
			existingAntreaClusterNetworkPolicies: []runtime.Object{cnp1},
			existingAntreaNetworkPolicies:        []runtime.Object{anp1},
			expectedNetworkPolicyStats: []statsv1alpha1.NetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      np2.Name,
						Namespace: np2.Namespace,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    10,
						Packets:  8,
						Sessions: 5,
					},
				},
			},
			expectedAntreaClusterNetworkPolicyStats: []statsv1alpha1.AntreaClusterNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: cnp1.Name,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    30,
						Packets:  16,
						Sessions: 10,
					},
				},
			},
			expectedAntreaNetworkPolicyStats: []statsv1alpha1.AntreaNetworkPolicyStats{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      anp1.Name,
						Namespace: anp1.Namespace,
					},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    50,
						Packets:  11,
						Sessions: 10,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AntreaPolicy, true)()

			stopCh := make(chan struct{})
			defer close(stopCh)
			client := fake.NewSimpleClientset(tt.existingNetworkPolicies...)
			informerFactory := informers.NewSharedInformerFactory(client, 12*time.Hour)
			crdClient := fakeversioned.NewSimpleClientset(append(tt.existingAntreaClusterNetworkPolicies, tt.existingAntreaNetworkPolicies...)...)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 12*time.Hour)
			a := NewAggregator(informerFactory.Networking().V1().NetworkPolicies(), crdInformerFactory.Crd().V1alpha1().ClusterNetworkPolicies(), crdInformerFactory.Crd().V1alpha1().NetworkPolicies())
			informerFactory.Start(stopCh)
			crdInformerFactory.Start(stopCh)
			expectedPolicyCount := len(tt.expectedNetworkPolicyStats) + len(tt.expectedAntreaClusterNetworkPolicyStats) + len(tt.expectedAntreaNetworkPolicyStats)
			runWrapper(t, a, expectedPolicyCount, tt.summaries)

			require.Equal(t, len(tt.expectedNetworkPolicyStats), len(a.ListNetworkPolicyStats("")))
			for _, stats := range tt.expectedNetworkPolicyStats {
				actualStats, exists := a.GetNetworkPolicyStats(stats.Namespace, stats.Name)
				require.True(t, exists)
				require.Equal(t, stats.TrafficStats, actualStats.TrafficStats)
			}
			assert.Equal(t, len(tt.expectedAntreaClusterNetworkPolicyStats), len(a.ListAntreaClusterNetworkPolicyStats()))
			for _, Stats := range tt.expectedAntreaClusterNetworkPolicyStats {
				actualStats, exists := a.GetAntreaClusterNetworkPolicyStats(Stats.Name)
				require.True(t, exists)
				require.Equal(t, Stats.TrafficStats, actualStats.TrafficStats)
				require.ElementsMatch(t, Stats.RuleTrafficStats, actualStats.RuleTrafficStats)
			}
			assert.Equal(t, len(tt.expectedAntreaNetworkPolicyStats), len(a.ListAntreaNetworkPolicyStats("")))
			for _, Stats := range tt.expectedAntreaNetworkPolicyStats {
				actualStats, exists := a.GetAntreaNetworkPolicyStats(Stats.Namespace, Stats.Name)
				require.True(t, exists)
				require.Equal(t, Stats.TrafficStats, actualStats.TrafficStats)
				require.ElementsMatch(t, Stats.RuleTrafficStats, actualStats.RuleTrafficStats)
			}
		})
	}
}

func TestDeleteNetworkPolicy(t *testing.T) {
	defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AntreaPolicy, true)()

	stopCh := make(chan struct{})
	defer close(stopCh)
	client := fake.NewSimpleClientset(np1)
	informerFactory := informers.NewSharedInformerFactory(client, 12*time.Hour)
	crdClient := fakeversioned.NewSimpleClientset(cnp1, anp1)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 12*time.Hour)
	a := NewAggregator(informerFactory.Networking().V1().NetworkPolicies(), crdInformerFactory.Crd().V1alpha1().ClusterNetworkPolicies(), crdInformerFactory.Crd().V1alpha1().NetworkPolicies())
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	summary := &controlplane.NodeStatsSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
		},
		NetworkPolicies: []controlplane.NetworkPolicyStats{
			{
				NetworkPolicy: controlplane.NetworkPolicyReference{UID: np1.UID},
				TrafficStats: statsv1alpha1.TrafficStats{
					Bytes:    10,
					Packets:  1,
					Sessions: 1,
				},
			},
		},
		AntreaClusterNetworkPolicies: []controlplane.NetworkPolicyStats{
			{
				NetworkPolicy: controlplane.NetworkPolicyReference{UID: cnp1.UID},
				RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
					{
						Name: "rule1",
						TrafficStats: statsv1alpha1.TrafficStats{
							Bytes:    30,
							Packets:  3,
							Sessions: 3,
						},
					},
				},
			},
		},
		AntreaNetworkPolicies: []controlplane.NetworkPolicyStats{
			{
				NetworkPolicy: controlplane.NetworkPolicyReference{UID: anp1.UID},
				RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
					{
						Name: "rule2",
						TrafficStats: statsv1alpha1.TrafficStats{
							Bytes:    30,
							Packets:  3,
							Sessions: 3,
						},
					},
				},
			},
		},
	}

	expectedPolicyCount := 3
	runWrapper(t, a, expectedPolicyCount, []*controlplane.NodeStatsSummary{summary})

	require.Equal(t, 1, len(a.ListNetworkPolicyStats("")))
	require.Equal(t, 1, len(a.ListAntreaClusterNetworkPolicyStats()))
	require.Equal(t, 1, len(a.ListAntreaNetworkPolicyStats("")))

	client.NetworkingV1().NetworkPolicies(np1.Namespace).Delete(context.TODO(), np1.Name, metav1.DeleteOptions{})
	crdClient.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), cnp1.Name, metav1.DeleteOptions{})
	crdClient.CrdV1alpha1().NetworkPolicies(anp1.Namespace).Delete(context.TODO(), anp1.Name, metav1.DeleteOptions{})
	// Event handlers are asynchronous, it's supposed to finish very soon.
	err := wait.PollImmediate(100*time.Millisecond, time.Second, func() (done bool, err error) {
		return len(a.ListNetworkPolicyStats("")) == 0 && len(a.ListAntreaClusterNetworkPolicyStats()) == 0 && len(a.ListAntreaNetworkPolicyStats("")) == 0, nil
	})
	assert.NoError(t, err)
}
