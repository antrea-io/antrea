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

package controllerinfo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

type fakeControllerQuerier struct{}

func (q *fakeControllerQuerier) GetControllerInfo(info *v1beta1.AntreaControllerInfo, partial bool) {}

func TestRESTList(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector labels.Selector
		expectedObj   runtime.Object
	}{
		{
			name:          "label selector selecting nothing",
			labelSelector: labels.Nothing(),
			expectedObj:   &v1beta1.AntreaControllerInfoList{},
		},
		{
			name:          "label selector selecting everything",
			labelSelector: labels.Everything(),
			expectedObj: &v1beta1.AntreaControllerInfoList{
				Items: []v1beta1.AntreaControllerInfo{
					{
						ObjectMeta: v1.ObjectMeta{
							Name: ControllerInfoResourceName,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST(&fakeControllerQuerier{})
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*v1beta1.AntreaControllerInfoList).Items, actualObj.(*v1beta1.AntreaControllerInfoList).Items)
		})
	}
}
