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

package nodelatencystats

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

func TestREST(t *testing.T) {
	r := NewREST()
	assert.Equal(t, &statsv1alpha1.NodeLatencyStats{}, r.New())
	assert.Equal(t, &statsv1alpha1.NodeLatencyStats{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTCreate(t *testing.T) {
	// Define the test case
	name := "create summary"
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	expectedObj := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	expectedErr := false

	// Execute the test case
	t.Run(name, func(t *testing.T) {
		r := NewREST()
		obj, err := r.Create(context.TODO(), summary, nil, nil)
		if expectedErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, expectedObj, obj)
		}
	})
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name        string
		summary     *statsv1alpha1.NodeLatencyStats
		nodeName    string
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name: "get summary",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName: "node1",
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			expectedErr: false,
		},
		{
			name: "get summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			expectedErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST()
			_, err := r.Create(context.TODO(), tt.summary, nil, nil)
			assert.Nil(t, err)
			obj, err := r.Get(context.TODO(), tt.nodeName, nil)
			if tt.expectedErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.expectedObj, obj)
			}
		})
	}
}

func TestRESTDelete(t *testing.T) {
	tests := []struct {
		name        string
		summary     *statsv1alpha1.NodeLatencyStats
		nodeName    string
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name: "delete summary",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName: "node1",
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			expectedErr: false,
		},
		{
			name: "delete summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			expectedErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST()
			_, err := r.Create(context.TODO(), tt.summary, nil, nil)
			assert.Nil(t, err)
			obj, deleted, err := r.Delete(context.TODO(), tt.nodeName, nil, nil)
			if tt.expectedErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.True(t, deleted)
				assert.Equal(t, tt.expectedObj, obj)
			}
		})
	}
}

func TestRESTList(t *testing.T) {
	tests := []struct {
		name        string
		summary     *statsv1alpha1.NodeLatencyStats
		options     *internalversion.ListOptions
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name: "list summary",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			options: &internalversion.ListOptions{
				Limit:    10,
				Continue: "",
			},
			expectedObj: &statsv1alpha1.NodeLatencyStatsList{
				Items: []statsv1alpha1.NodeLatencyStats{
					{
						ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
						PeerNodeLatencyStats: nil,
					},
				},
			},
			expectedErr: false,
		},
		{
			name: "list summary",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			options: &internalversion.ListOptions{
				Limit:    0,
				Continue: "",
			},
			expectedObj: &statsv1alpha1.NodeLatencyStatsList{
				Items: []statsv1alpha1.NodeLatencyStats{
					{
						ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
						PeerNodeLatencyStats: nil,
					},
				},
			},
			expectedErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST()
			_, err := r.Create(context.TODO(), tt.summary, nil, nil)
			assert.Nil(t, err)
			obj, err := r.List(context.TODO(), tt.options)
			if tt.expectedErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.expectedObj, obj)
			}
		})
	}
}

func TestRESTConvertToTable(t *testing.T) {
	name := "convert to table"
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	expectedObj := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	expectedErr := false

	t.Run(name, func(t *testing.T) {
		r := NewREST()
		_, err := r.Create(context.TODO(), summary, nil, nil)
		assert.Nil(t, err)
		obj, err := r.ConvertToTable(context.TODO(), summary, nil)
		if expectedErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, expectedObj, obj.Rows[0].Object.Object)
		}
	})
}
