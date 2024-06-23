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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
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
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	expectedObj := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}

	r := NewREST()
	ctx := context.Background()

	obj, err := r.Create(ctx, summary, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedObj, obj)
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name        string
		summary     *statsv1alpha1.NodeLatencyStats
		nodeName    string
		expectedObj runtime.Object
		err         error
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
			err: nil,
		},
		{
			name: "get summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			err:         errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), "node2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST()
			ctx := context.Background()

			_, err := r.Create(ctx, tt.summary, nil, nil)
			require.NoError(t, err)

			obj, err := r.Get(ctx, tt.nodeName, nil)
			if tt.err != nil {
				assert.EqualError(t, tt.err, err.Error())
			} else {
				require.NoError(t, err)
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
		err         error
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
			err: nil,
		},
		{
			name: "delete summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			err:         errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), "node2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewREST()
			ctx := context.Background()

			_, err := r.Create(ctx, tt.summary, nil, nil)
			require.NoError(t, err)
			obj, deleted, err := r.Delete(ctx, tt.nodeName, nil, nil)
			if tt.err != nil {
				assert.EqualError(t, tt.err, err.Error())
			} else {
				require.NoError(t, err)
				assert.True(t, deleted)
				assert.Equal(t, tt.expectedObj, obj)
			}
		})
	}
}

func TestRESTList(t *testing.T) {
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: nil,
	}
	options := &internalversion.ListOptions{
		Limit:    10,
		Continue: "",
	}
	expectedObj := &statsv1alpha1.NodeLatencyStatsList{
		Items: []statsv1alpha1.NodeLatencyStats{
			{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
		},
	}

	r := NewREST()
	ctx := context.Background()

	_, err := r.Create(ctx, summary, nil, nil)
	require.NoError(t, err)
	objs, err := r.List(ctx, options)
	require.NoError(t, err)
	assert.Equal(t, expectedObj, objs)
}

func TestRESTConvertToTable(t *testing.T) {
	mockTime := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: []statsv1alpha1.PeerNodeLatencyStats{
			{
				NodeName: "node2",
				TargetIPLatencyStats: []statsv1alpha1.TargetIPLatencyStats{
					{
						TargetIP:                   "192.168.0.1",
						LastSendTime:               metav1.Time{Time: mockTime},
						LastRecvTime:               metav1.Time{Time: mockTime},
						LastMeasuredRTTNanoseconds: 0,
					},
				},
			},
		},
	}
	expectedObj := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		PeerNodeLatencyStats: []statsv1alpha1.PeerNodeLatencyStats{
			{
				NodeName: "node2",
				TargetIPLatencyStats: []statsv1alpha1.TargetIPLatencyStats{
					{
						TargetIP:                   "192.168.0.1",
						LastSendTime:               metav1.Time{Time: mockTime},
						LastRecvTime:               metav1.Time{Time: mockTime},
						LastMeasuredRTTNanoseconds: 0,
					},
				},
			},
		},
	}
	expectedCells := []interface{}{"node1", 1, "0s", "0s"}

	r := NewREST()
	ctx := context.Background()

	_, err := r.Create(ctx, summary, nil, nil)
	require.NoError(t, err)
	obj, err := r.ConvertToTable(ctx, summary, nil)
	require.NoError(t, err)
	assert.Equal(t, expectedObj, obj.Rows[0].Object.Object)
	assert.Equal(t, expectedCells, obj.Rows[0].Cells)
}
