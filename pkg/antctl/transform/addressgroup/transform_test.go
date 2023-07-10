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

package addressgroup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func TestListTransform(t *testing.T) {
	var agA = cpv1beta.AddressGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "a",
			UID:               "abc",
			CreationTimestamp: metav1.Now(),
		},
	}
	var agB = cpv1beta.AddressGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "b",
			UID:               "aaa",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(1)},
		},
	}
	var agC = cpv1beta.AddressGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "c",
			UID:               "abb",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(2)},
		},
	}

	var agList = &cpv1beta.AddressGroupList{
		Items: []cpv1beta.AddressGroup{agA, agC, agB},
	}

	tests := []struct {
		name             string
		opts             map[string]string
		expectedResponse []Response
		expectedError    string
	}{
		{
			name: "sort by name",
			opts: map[string]string{
				"sort-by": ".metadata.name",
			},
			expectedResponse: []Response{{Name: agA.Name}, {Name: agB.Name}, {Name: agC.Name}},
		},
		{
			name: "sort by uid",
			opts: map[string]string{
				"sort-by": ".metadata.uid",
			},
			expectedResponse: []Response{{Name: agB.Name}, {Name: agC.Name}, {Name: agA.Name}},
		},
		{
			name: "sort by creationTimestamp",
			opts: map[string]string{
				"sort-by": ".metadata.creationTimestamp",
			},
			expectedResponse: []Response{{Name: agA.Name}, {Name: agB.Name}, {Name: agC.Name}},
		},
		{
			name: "sort by name default",
			opts: map[string]string{
				"sort-by": "",
			},
			expectedResponse: []Response{{Name: agA.Name}, {Name: agB.Name}, {Name: agC.Name}},
		},
		{
			name: "invalid case",
			opts: map[string]string{
				"sort-by": "effective",
			},
			expectedError: "couldn't find any field with path \"{.effective}\" in the list of objects",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := listTransform(agList, tt.opts)
			if tt.expectedError == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, result)
			} else {
				assert.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}
