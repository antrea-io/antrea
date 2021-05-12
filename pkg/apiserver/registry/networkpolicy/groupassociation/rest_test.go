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

package groupassociation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"

	"antrea.io/antrea/pkg/apis/controlplane"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/k8s"
)

type fakeQuerier struct {
	groups map[string][]antreatypes.Group
}

func (q fakeQuerier) GetAssociatedGroups(name, namespace string) ([]antreatypes.Group, error) {
	memberKey := k8s.NamespacedName(namespace, name)
	if refs, ok := q.groups[memberKey]; ok {
		return refs, nil
	}
	return []antreatypes.Group{}, nil
}

func TestRESTGet(t *testing.T) {
	groups := map[string][]antreatypes.Group{
		"default/podA": {
			{
				UID:  "groupUID1",
				Name: "cg1",
			},
		},
		"default/podB": {
			{
				UID:  "groupUID2",
				Name: "cg2",
			},
			{
				UID:  "groupUID3",
				Name: "cg3",
			},
		},
	}
	tests := []struct {
		name        string
		podName     string
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name:    "single-group-ref",
			podName: "podA",
			expectedObj: &controlplane.GroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg1",
						UID:       "groupUID1",
					},
				},
			},
			expectedErr: false,
		},
		{
			name:    "multi-group-ref",
			podName: "podB",
			expectedObj: &controlplane.GroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg2",
						UID:       "groupUID2",
					},
					{
						Namespace: "",
						Name:      "cg3",
						UID:       "groupUID3",
					},
				},
			},
			expectedErr: false,
		},
		{
			name:    "no-group-ref",
			podName: "podC",
			expectedObj: &controlplane.GroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{},
			},
			expectedErr: false,
		},
	}
	rest := NewREST(fakeQuerier{groups: groups})
	for _, tt := range tests {
		actualGroupList, err := rest.Get(request.NewDefaultContext(), tt.podName, &metav1.GetOptions{})
		if tt.expectedErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tt.expectedObj, actualGroupList)
	}
}
