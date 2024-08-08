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

	clocktesting "k8s.io/utils/clock/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

func TestREST(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())
	r := newRESTWithClock(fakeClock)
	assert.Equal(t, &statsv1alpha1.NodeLatencyStats{}, r.New())
	assert.Equal(t, &statsv1alpha1.NodeLatencyStats{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTCreate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	const timeStep = 1 * time.Minute
	tests := []struct {
		name        string
		summary     *statsv1alpha1.NodeLatencyStats
		expectedObj *statsv1alpha1.NodeLatencyStats
	}{
		{
			name: "create with existing timestamp",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
		},
		{
			name: "create with no existing timestamp",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1"},
				PeerNodeLatencyStats: nil,
			},
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				// the test case advances the clock by timeStep
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now.Add(timeStep)}},
				PeerNodeLatencyStats: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(now)
			r := newRESTWithClock(fakeClock)
			fakeClock.Step(timeStep)
			obj, err := r.Create(ctx, tt.summary, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedObj, obj)
		})
	}
}

func TestRESTGet(t *testing.T) {
	now := time.Now()
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
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			nodeName: "node1",
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			err: nil,
		},
		{
			name: "get summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			err:         errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), "node2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(now)
			r := newRESTWithClock(fakeClock)
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
	now := time.Now()
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
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			nodeName: "node1",
			expectedObj: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			err: nil,
		},
		{
			name: "delete summary not found",
			summary: &statsv1alpha1.NodeLatencyStats{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
			nodeName:    "node2",
			expectedObj: nil,
			err:         errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), "node2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(now)
			r := newRESTWithClock(fakeClock)
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
	now := time.Now()
	fakeClock := clocktesting.NewFakeClock(now)
	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
		PeerNodeLatencyStats: nil,
	}
	expectedObj := &statsv1alpha1.NodeLatencyStatsList{
		Items: []statsv1alpha1.NodeLatencyStats{
			{
				ObjectMeta:           metav1.ObjectMeta{Name: "node1", CreationTimestamp: metav1.Time{Time: now}},
				PeerNodeLatencyStats: nil,
			},
		},
	}

	r := newRESTWithClock(fakeClock)
	ctx := context.Background()

	_, err := r.Create(ctx, summary, nil, nil)
	require.NoError(t, err)
	objs, err := r.List(ctx, nil)
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
						TargetIP:                   "192.168.0.2",
						LastSendTime:               metav1.Time{Time: mockTime},
						LastRecvTime:               metav1.Time{Time: mockTime},
						LastMeasuredRTTNanoseconds: 1000000,
					},
				},
			},
			{
				NodeName: "node3",
				TargetIPLatencyStats: []statsv1alpha1.TargetIPLatencyStats{
					{
						TargetIP:                   "192.168.0.3",
						LastSendTime:               metav1.Time{Time: mockTime},
						LastRecvTime:               metav1.Time{Time: mockTime},
						LastMeasuredRTTNanoseconds: 2000000,
					},
				},
			},
		},
	}
	expectedCells := []interface{}{"node1", 2, "1.5ms", "2ms"}

	r := NewREST()
	ctx := context.Background()

	_, err := r.Create(ctx, summary, nil, nil)
	require.NoError(t, err)
	obj, err := r.ConvertToTable(ctx, summary, nil)
	require.NoError(t, err)
	assert.Equal(t, expectedCells, obj.Rows[0].Cells)
}
