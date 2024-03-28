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
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientset "k8s.io/client-go/kubernetes"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	system "antrea.io/antrea/pkg/apis/system/v1beta1"
)

type fakeControllerQuerier struct{}

func (q *fakeControllerQuerier) GetControllerInfo(info *v1beta1.AntreaControllerInfo, partial bool) {}

func (q *fakeControllerQuerier) GetK8sClient() clientset.Interface { return nil }

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &v1beta1.AntreaControllerInfo{}, r.New())
	assert.Equal(t, &v1beta1.AntreaControllerInfoList{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name        string
		objName     string
		expectedObj runtime.Object
		expectedErr error
	}{
		{
			name:    "name matches",
			objName: v1beta1.AntreaControllerInfoResourceName,
			expectedObj: &v1beta1.AntreaControllerInfo{
				ObjectMeta: v1.ObjectMeta{
					Name: v1beta1.AntreaControllerInfoResourceName,
				},
			},
		},
		{
			name:        "name does not match",
			objName:     "foo",
			expectedErr: errors.NewNotFound(system.Resource("controllerinfos"), "foo"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST(&fakeControllerQuerier{})
			actualObj, err := r.Get(context.TODO(), tt.objName, &v1.GetOptions{})
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedObj, actualObj)
		})
	}
}

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
							Name: v1beta1.AntreaControllerInfoResourceName,
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
