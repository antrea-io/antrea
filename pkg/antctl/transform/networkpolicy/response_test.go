// Copyright 2023 Antrea Authors
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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func TestListTransform(t *testing.T) {
	var npA = cpv1beta.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "a",
			UID:               "abc",
			CreationTimestamp: metav1.Now(),
		},
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Name: "a",
		},
		TierPriority: ptr.To[int32](260),
		Priority:     ptr.To(5.7),
	}
	var npB = cpv1beta.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "b",
			UID:               "aaa",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(1)},
		},
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Name: "b",
		},
		TierPriority: ptr.To[int32](260),
		Priority:     ptr.To(7.8),
	}
	var npC = cpv1beta.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "c",
			UID:               "abb",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(2)},
		},
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Name: "c",
		},
		TierPriority: ptr.To[int32](200),
		Priority:     ptr.To[float64](8),
	}
	var npD = cpv1beta.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "d",
			UID:               "aab",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(3)},
		},
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Name: "d",
		},
	}
	var npE = cpv1beta.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "e",
			UID:               "bbb",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(4)},
		},
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Name: "e",
		},
	}

	var npList1 = &cpv1beta.NetworkPolicyList{
		Items: []cpv1beta.NetworkPolicy{npA, npC, npB},
	}
	var npList2 = &cpv1beta.NetworkPolicyList{
		Items: []cpv1beta.NetworkPolicy{npA, npE, npD, npC},
	}

	tests := []struct {
		name             string
		opts             map[string]string
		npList           *cpv1beta.NetworkPolicyList
		expectedResponse interface{}
		expectedError    string
	}{
		{
			name: "sort by name",
			opts: map[string]string{
				"sort-by": ".sourceRef.name",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npA}, {&npB}, {&npC}},
		},
		{
			name: "sort by uid",
			opts: map[string]string{
				"sort-by": ".metadata.uid",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npB}, {&npC}, {&npA}},
		},
		{
			name: "sort by creationTimestamp",
			opts: map[string]string{
				"sort-by": ".metadata.creationTimestamp",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npA}, {&npB}, {&npC}},
		},
		{
			name: "sort by effectivePriority",
			opts: map[string]string{
				"sort-by": "effectivePriority",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npC}, {&npA}, {&npB}},
		},
		{
			name: "sort by name default",
			opts: map[string]string{
				"sort-by": "",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npA}, {&npB}, {&npC}},
		},
		{
			name: "sort by effectivePriority including K8s np",
			opts: map[string]string{
				"sort-by": "effectivePriority",
			},
			npList:           npList2,
			expectedResponse: []Response{{&npC}, {&npD}, {&npE}, {&npA}},
		},
		{
			name: "invalid case",
			opts: map[string]string{
				"sort-by": "effective",
			},
			npList:           npList1,
			expectedResponse: []Response{{&npA}, {&npB}, {&npC}},
			expectedError:    "couldn't find any field with path \"{.effective}\" in the list of objects",
		},
		{
			name:             "empty case",
			npList:           &cpv1beta.NetworkPolicyList{Items: []cpv1beta.NetworkPolicy{}},
			expectedResponse: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := listTransform(tt.npList, tt.opts)
			if tt.expectedError == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, result)
			} else {
				assert.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}

func TestEvaluationResponseTransform(t *testing.T) {
	test := EvaluationResponse{&cpv1beta.NetworkPolicyEvaluation{}}
	assert.Equal(t, []string{"NAME", "NAMESPACE", "POLICY-TYPE", "RULE-INDEX", "DIRECTION"}, test.GetTableHeader())
	assert.False(t, test.SortRows())
	assert.Equal(t, []string{"", "", "", "", ""}, test.GetTableRow(32))
	test.Response = &cpv1beta.NetworkPolicyEvaluationResponse{
		NetworkPolicy: cpv1beta.NetworkPolicyReference{
			Type:      cpv1beta.K8sNetworkPolicy,
			Namespace: "ns",
			Name:      "testName",
		},
		RuleIndex: 10,
		Rule:      cpv1beta.RuleRef{Direction: cpv1beta.DirectionIn},
	}
	assert.Equal(t, []string{"testName", "ns", "K8sNetworkPolicy", "10", "In"}, test.GetTableRow(32))
}
