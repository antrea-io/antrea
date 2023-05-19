// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package supportbundlecollection

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/supportbundlecollection/store"
	"antrea.io/antrea/pkg/controller/types"
)

func TestRESTList(t *testing.T) {
	testDuration := "2h"
	expireMinutes, _ := time.ParseDuration("120m")
	expireAt := v1.NewTime(time.Now().Add(expireMinutes))
	tests := []struct {
		name                     string
		supportBundleCollections []*types.SupportBundleCollection
		labelSelector            labels.Selector
		expectedObj              runtime.Object
	}{
		{
			name: "label selector selecting nothing",
			supportBundleCollections: []*types.SupportBundleCollection{
				{
					Name: "foo",
				},
			},
			labelSelector: labels.Nothing(),
			expectedObj:   &controlplane.SupportBundleCollectionList{},
		},
		{
			name: "label selector selecting everything",
			supportBundleCollections: []*types.SupportBundleCollection{
				{
					Name:      "foo1",
					ExpiredAt: expireAt,
					SinceTime: testDuration,
					FileServer: v1alpha1.BundleFileServer{
						URL: "https://1.1.1.1/bundles/upload",
					},
					Authentication: controlplane.BundleServerAuthConfiguration{
						APIKey: "123456789",
					},
				},
				{
					Name: "foo2",
					FileServer: v1alpha1.BundleFileServer{
						URL: "https://1.1.1.1/bundles/upload",
					},
					Authentication: controlplane.BundleServerAuthConfiguration{
						BearerToken: "acretdfee53d==",
					},
					ExpiredAt: expireAt,
				},
			},
			labelSelector: labels.Everything(),
			expectedObj: &controlplane.SupportBundleCollectionList{
				Items: []controlplane.SupportBundleCollection{
					{
						ObjectMeta: v1.ObjectMeta{
							Name: "foo1",
						},
						ExpiredAt: expireAt,
						SinceTime: testDuration,
						FileServer: controlplane.BundleFileServer{
							URL: "https://1.1.1.1/bundles/upload",
						},
						Authentication: controlplane.BundleServerAuthConfiguration{
							APIKey: "123456789",
						},
					},
					{
						ObjectMeta: v1.ObjectMeta{
							Name: "foo2",
						},
						ExpiredAt: expireAt,
						FileServer: controlplane.BundleFileServer{
							URL: "https://1.1.1.1/bundles/upload",
						},
						Authentication: controlplane.BundleServerAuthConfiguration{
							BearerToken: "acretdfee53d==",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewSupportBundleCollectionStore()
			for _, obj := range tt.supportBundleCollections {
				storage.Create(obj)
			}
			r := NewREST(storage)
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*controlplane.SupportBundleCollectionList).Items, actualObj.(*controlplane.SupportBundleCollectionList).Items)
			for _, expObj := range tt.expectedObj.(*controlplane.SupportBundleCollectionList).Items {
				obj, err := r.Get(context.Background(), expObj.Name, &v1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, expObj, *(obj.(*controlplane.SupportBundleCollection)))
			}
		})
	}
}

func TestWatch(t *testing.T) {
	storage := store.NewSupportBundleCollectionStore()
	expireAt := v1.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)
	collection := &types.SupportBundleCollection{
		Name:      "foo1",
		ExpiredAt: expireAt,
		SinceTime: "2h",
		FileServer: v1alpha1.BundleFileServer{
			URL: "https://1.1.1.1/bundles/upload",
		},
		Authentication: controlplane.BundleServerAuthConfiguration{
			APIKey: "123456789",
		},
	}

	r := NewREST(storage)
	watcher, err := r.Watch(context.TODO(), &internalversion.ListOptions{})
	require.NoError(t, err)
	<-watcher.ResultChan()
	err = storage.Create(collection)
	require.NoError(t, err)
	ev := <-watcher.ResultChan()
	assert.Equal(t, watch.Added, ev.Type)
	watchedObj, ok := ev.Object.(*controlplane.SupportBundleCollection)
	assert.True(t, ok)
	assert.Equal(t, collection.Name, watchedObj.Name)
	err = storage.Delete(collection.Name)
	require.NoError(t, err)
	ev = <-watcher.ResultChan()
	assert.Equal(t, watch.Deleted, ev.Type)
	watchedObj, ok = ev.Object.(*controlplane.SupportBundleCollection)
	assert.True(t, ok)
	assert.Equal(t, collection.Name, watchedObj.Name)
}

func TestWatchWithFilter(t *testing.T) {
	storage := store.NewSupportBundleCollectionStore()
	expireAt := v1.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)
	collection := &types.SupportBundleCollection{
		SpanMeta: types.SpanMeta{
			NodeNames: sets.New[string]("n1"),
		},
		Name:      "foo1",
		ExpiredAt: expireAt,
		SinceTime: "2h",
		FileServer: v1alpha1.BundleFileServer{
			URL: "https://1.1.1.1/bundles/upload",
		},
		Authentication: controlplane.BundleServerAuthConfiguration{
			APIKey: "123456789",
		},
	}

	err := storage.Create(collection)
	require.NoError(t, err)
	for _, tc := range []struct {
		nodeName string
		received bool
	}{
		{nodeName: "n1", received: true},
		{nodeName: "n2", received: false},
	} {
		r := NewREST(storage)
		watcher, err := r.Watch(context.TODO(), &internalversion.ListOptions{FieldSelector: fields.OneTermEqualSelector("nodeName", tc.nodeName)})
		require.NoError(t, err)
		ev := <-watcher.ResultChan()
		if tc.received {
			assert.Equal(t, watch.Added, ev.Type)
			watchedObj, ok := ev.Object.(*controlplane.SupportBundleCollection)
			assert.True(t, ok)
			assert.Equal(t, collection.Name, watchedObj.Name)
			ev = <-watcher.ResultChan()
			assert.Equal(t, watch.Bookmark, ev.Type)
		} else {
			assert.Equal(t, watch.Bookmark, ev.Type)
		}
	}
}
