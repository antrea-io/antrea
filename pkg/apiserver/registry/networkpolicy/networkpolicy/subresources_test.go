// Copyright 2022 Antrea Authors
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/pkg/apis/controlplane"
)

type fakeCollector struct {
	gotStatus *controlplane.NetworkPolicyStatus
}

func (f *fakeCollector) UpdateStatus(status *controlplane.NetworkPolicyStatus) error {
	f.gotStatus = status
	return nil
}

func TestStatusREST(t *testing.T) {
	r := NewStatusREST(nil)
	assert.Equal(t, &controlplane.NetworkPolicyStatus{}, r.New())
}

func TestStatusRESTCreate(t *testing.T) {
	tests := []struct {
		name                string
		objName             string
		obj                 runtime.Object
		expectedReturnedObj runtime.Object
		expectedErr         error
		expectedStatus      *controlplane.NetworkPolicyStatus
	}{
		{
			name:    "succeed",
			objName: "foo",
			obj: &controlplane.NetworkPolicyStatus{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
				Nodes: []controlplane.NetworkPolicyNodeStatus{
					{NodeName: "node1", Generation: 1},
				},
			},
			expectedReturnedObj: &v1.Status{Status: v1.StatusSuccess},
			expectedStatus: &controlplane.NetworkPolicyStatus{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
				Nodes: []controlplane.NetworkPolicyNodeStatus{
					{NodeName: "node1", Generation: 1},
				},
			},
		},
		{
			name:    "unexpected type",
			objName: "foo",
			obj: &controlplane.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedErr: errors.NewBadRequest("not a NetworkPolicyStatus object: *controlplane.NetworkPolicy"),
		},
		{
			name:    "mismatch name",
			objName: "foo",
			obj: &controlplane.NetworkPolicyStatus{
				ObjectMeta: v1.ObjectMeta{
					Name: "bar",
				},
			},
			expectedErr: errors.NewBadRequest("name in URL does not match name in NetworkPolicyStatus object"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := &fakeCollector{}
			r := NewStatusREST(collector)
			actualObj, err := r.Create(context.TODO(), tt.objName, tt.obj, nil, &v1.CreateOptions{})
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedReturnedObj, actualObj)
		})
	}
}
