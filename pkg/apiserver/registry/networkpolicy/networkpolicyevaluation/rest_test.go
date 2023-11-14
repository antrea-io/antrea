// Copyright 2024 Antrea Authors
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

package networkpolicyevaluation

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/pkg/apis/controlplane"
	queriermock "antrea.io/antrea/pkg/controller/networkpolicy/testing"
)

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &controlplane.NetworkPolicyEvaluation{}, r.New())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTCreate(t *testing.T) {
	request := controlplane.NetworkPolicyEvaluationRequest{Source: controlplane.Entity{Pod: &controlplane.PodReference{Namespace: "ns", Name: "pod1"}}, Destination: controlplane.Entity{Pod: &controlplane.PodReference{Namespace: "ns", Name: "pod2"}}}
	tests := []struct {
		name                string
		obj                 runtime.Object
		expectedReturnedObj runtime.Object
		expectedErr         error
		mockResponse        *controlplane.NetworkPolicyEvaluationResponse
		mockErr             error
	}{
		{
			name: "Succeed",
			obj: &controlplane.NetworkPolicyEvaluation{
				Request: &request,
			},
			expectedReturnedObj: &controlplane.NetworkPolicyEvaluation{
				Request: &request,
				Response: &controlplane.NetworkPolicyEvaluationResponse{
					NetworkPolicy: controlplane.NetworkPolicyReference{Name: "test"},
					Rule:          controlplane.RuleRef{Direction: controlplane.DirectionIn},
				},
			},
			mockResponse: &controlplane.NetworkPolicyEvaluationResponse{
				NetworkPolicy: controlplane.NetworkPolicyReference{Name: "test"},
				Rule:          controlplane.RuleRef{Direction: controlplane.DirectionIn},
			},
		},
		{
			name: "Query error",
			obj: &controlplane.NetworkPolicyEvaluation{
				Request: &request,
			},
			mockErr:     fmt.Errorf("querier error"),
			expectedErr: errors.NewInternalError(fmt.Errorf("querier error")),
		},
		{
			name: "Unexpected type",
			obj: &controlplane.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedErr: errors.NewBadRequest("not a NetworkPolicyEvaluation object: *controlplane.NetworkPolicy"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockQuerier := queriermock.NewMockPolicyRuleQuerier(mockCtrl)
			if tt.mockResponse != nil || tt.mockErr != nil {
				mockQuerier.EXPECT().QueryNetworkPolicyEvaluation(tt.obj.(*controlplane.NetworkPolicyEvaluation).Request).Return(tt.mockResponse, tt.mockErr)
			}
			r := NewREST(mockQuerier)
			actualObj, err := r.Create(context.TODO(), tt.obj, nil, &v1.CreateOptions{})
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedReturnedObj, actualObj)
		})
	}
}
