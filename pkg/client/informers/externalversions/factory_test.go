// Copyright 2025 Antrea Authors
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

package externalversions

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	versioned "antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

// newTestClientset returns a fake Clientset for tests.
// Note: fakeversioned.NewSimpleClientset is backed by a simple object tracker and does
// not implement field management required for full server-side apply testing.
// When `NewClientset` (with applyconfig support) is available from generated code,
// it should be preferred for tests that exercise server-side apply behaviour.
func newTestClientset(objects ...runtime.Object) versioned.Interface {
	return fakeversioned.NewSimpleClientset(objects...)
}

func TestNewSharedInformerFactory(t *testing.T) {
	client := newTestClientset()
	resyncPeriod := 30 * time.Second

	factory := NewSharedInformerFactory(client, resyncPeriod)

	assert.NotNil(t, factory)
	assert.IsType(t, &sharedInformerFactory{}, factory)

	sif := factory.(*sharedInformerFactory)
	assert.Equal(t, client, sif.client)
	assert.Equal(t, resyncPeriod, sif.defaultResync)
	assert.Equal(t, v1.NamespaceAll, sif.namespace)
	assert.NotNil(t, sif.informers)
	assert.NotNil(t, sif.startedInformers)
	assert.NotNil(t, sif.customResync)
}

func TestNewSharedInformerFactoryWithOptions(t *testing.T) {
	client := newTestClientset()
	resyncPeriod := 30 * time.Second
	namespace := "test-namespace"
	customResync := time.Minute
	tweakFunc := func(options *v1.ListOptions) {
		options.LabelSelector = "app=test"
	}
	transformFunc := func(obj interface{}) (interface{}, error) {
		return obj, nil
	}

	tests := []struct {
		name     string
		options  []SharedInformerOption
		validate func(*testing.T, *sharedInformerFactory)
	}{
		{
			name:    "WithNamespace",
			options: []SharedInformerOption{WithNamespace(namespace)},
			validate: func(t *testing.T, f *sharedInformerFactory) {
				assert.Equal(t, namespace, f.namespace)
			},
		},
		{
			name:    "WithTweakListOptions",
			options: []SharedInformerOption{WithTweakListOptions(tweakFunc)},
			validate: func(t *testing.T, f *sharedInformerFactory) {
				assert.NotNil(t, f.tweakListOptions)
			},
		},
		{
			name: "WithCustomResyncConfig",
			options: []SharedInformerOption{
				WithCustomResyncConfig(map[v1.Object]time.Duration{
					&crdv1beta1.ClusterNetworkPolicy{}: customResync,
				}),
			},
			validate: func(t *testing.T, f *sharedInformerFactory) {
				assert.Len(t, f.customResync, 1)
			},
		},
		{
			name:    "WithTransform",
			options: []SharedInformerOption{WithTransform(transformFunc)},
			validate: func(t *testing.T, f *sharedInformerFactory) {
				assert.NotNil(t, f.transform)
			},
		},
		{
			name: "MultipleOptions",
			options: []SharedInformerOption{
				WithNamespace(namespace),
				WithTweakListOptions(tweakFunc),
				WithTransform(transformFunc),
			},
			validate: func(t *testing.T, f *sharedInformerFactory) {
				assert.Equal(t, namespace, f.namespace)
				assert.NotNil(t, f.tweakListOptions)
				assert.NotNil(t, f.transform)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewSharedInformerFactoryWithOptions(client, resyncPeriod, tt.options...)
			require.NotNil(t, factory)

			sif := factory.(*sharedInformerFactory)
			tt.validate(t, sif)
		})
	}
}

func TestSharedInformerFactory_Start(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Create an informer to ensure there's something to start
	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()

	// Start should not block
	done := make(chan bool)
	go func() {
		factory.Start(stopCh)
		done <- true
	}()

	select {
	case <-done:
		// Start returned as expected
	case <-time.After(2 * time.Second):
		t.Fatal("Start() blocked unexpectedly")
	}

	sif := factory.(*sharedInformerFactory)
	assert.True(t, len(sif.startedInformers) > 0)
}

func TestSharedInformerFactory_StartMultipleTimes(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()

	// Start multiple times should be safe
	factory.Start(stopCh)
	factory.Start(stopCh)
	factory.Start(stopCh)

	sif := factory.(*sharedInformerFactory)
	assert.True(t, len(sif.startedInformers) > 0)
}

func TestSharedInformerFactory_WaitForCacheSync(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	_ = factory.Crd().V1beta1().NetworkPolicies().Informer()

	factory.Start(stopCh)

	syncResults := factory.WaitForCacheSync(stopCh)

	assert.NotEmpty(t, syncResults)
	for informerType, synced := range syncResults {
		assert.True(t, synced, "Informer %v should be synced", informerType)
	}
}

func TestSharedInformerFactory_WaitForCacheSyncBeforeStart(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()

	// Call WaitForCacheSync before Start - should return empty map
	syncResults := factory.WaitForCacheSync(stopCh)
	assert.Empty(t, syncResults)
}

func TestSharedInformerFactory_Shutdown(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()

	factory.Start(stopCh)

	// Shutdown should not block indefinitely
	done := make(chan bool)
	go func() {
		close(stopCh)
		factory.Shutdown()
		done <- true
	}()

	select {
	case <-done:
		// Shutdown completed
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown() blocked for too long")
	}

	sif := factory.(*sharedInformerFactory)
	assert.True(t, sif.shuttingDown)
}

func TestSharedInformerFactory_ShutdownMultipleTimes(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	close(stopCh)

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	factory.Start(stopCh)

	// Multiple Shutdown calls should be safe
	factory.Shutdown()
	factory.Shutdown()
	factory.Shutdown()

	sif := factory.(*sharedInformerFactory)
	assert.True(t, sif.shuttingDown)
}

func TestSharedInformerFactory_StartAfterShutdown(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	close(stopCh)

	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	factory.Start(stopCh)
	factory.Shutdown()

	// Start after Shutdown should not start any informers
	newStopCh := make(chan struct{})
	defer close(newStopCh)

	factory.Start(newStopCh)

	sif := factory.(*sharedInformerFactory)
	assert.True(t, sif.shuttingDown)
}

func TestSharedInformerFactory_InformerFor(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 30*time.Second).(*sharedInformerFactory)

	obj := &crdv1beta1.ClusterNetworkPolicy{}
	newFunc := func(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			nil,
			obj,
			resyncPeriod,
			cache.Indexers{},
		)
	}

	informer1 := factory.InformerFor(obj, newFunc)
	assert.NotNil(t, informer1)

	// Requesting the same informer should return the same instance
	informer2 := factory.InformerFor(obj, newFunc)
	assert.Equal(t, informer1, informer2)

	assert.Len(t, factory.informers, 1)
}

func TestSharedInformerFactory_InformerForWithCustomResync(t *testing.T) {
	client := newTestClientset()
	customResyncPeriod := time.Minute
	factory := NewSharedInformerFactoryWithOptions(
		client,
		30*time.Second,
		WithCustomResyncConfig(map[v1.Object]time.Duration{
			&crdv1beta1.ClusterNetworkPolicy{}: customResyncPeriod,
		}),
	).(*sharedInformerFactory)

	obj := &crdv1beta1.ClusterNetworkPolicy{}
	receivedResyncPeriod := time.Duration(0)
	newFunc := func(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		receivedResyncPeriod = resyncPeriod
		return cache.NewSharedIndexInformer(
			nil,
			obj,
			resyncPeriod,
			cache.Indexers{},
		)
	}

	_ = factory.InformerFor(obj, newFunc)
	assert.Equal(t, customResyncPeriod, receivedResyncPeriod)
}

func TestSharedInformerFactory_ForResource(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	tests := []struct {
		name        string
		resource    schema.GroupVersionResource
		shouldError bool
	}{
		{
			name: "ClusterNetworkPolicy",
			resource: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "clusternetworkpolicies",
			},
			shouldError: false,
		},
		{
			name: "NetworkPolicy",
			resource: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "networkpolicies",
			},
			shouldError: false,
		},
		{
			name: "ExternalEntity",
			resource: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha2",
				Resource: "externalentities",
			},
			shouldError: false,
		},
		{
			name: "InvalidResource",
			resource: schema.GroupVersionResource{
				Group:    "invalid",
				Version:  "v1",
				Resource: "invalid",
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			informer, err := factory.ForResource(tt.resource)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, informer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, informer)
			}
		})
	}
}

func TestSharedInformerFactory_Crd(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	crdInterface := factory.Crd()
	assert.NotNil(t, crdInterface)

	// Verify we can access version interfaces
	assert.NotNil(t, crdInterface.V1alpha1())
	assert.NotNil(t, crdInterface.V1alpha2())
	assert.NotNil(t, crdInterface.V1beta1())
}

func TestSharedInformerFactory_InformerWithTransform(t *testing.T) {
	client := newTestClientset()
	transformFunc := func(obj interface{}) (interface{}, error) {
		return obj, nil
	}

	factory := NewSharedInformerFactoryWithOptions(
		client,
		0,
		WithTransform(transformFunc),
	)

	// Create an informer
	informer := factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	assert.NotNil(t, informer)

	// The transform function should be set on the informer
	sif := factory.(*sharedInformerFactory)
	assert.NotNil(t, sif.transform)
}

func TestSharedInformerFactory_InformerLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create some test objects
	cnp := &crdv1beta1.ClusterNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-cnp",
		},
	}

	client := newTestClientset(cnp)
	factory := NewSharedInformerFactory(client, 0)

	// Get informer
	informer := factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()

	// Add an event handler to verify informer is working
	eventReceived := make(chan bool, 1)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			eventReceived <- true
		},
	})

	// Start factory
	factory.Start(ctx.Done())

	// Wait for cache sync
	synced := factory.WaitForCacheSync(ctx.Done())
	assert.NotEmpty(t, synced)

	// Verify cache is synced
	assert.True(t, cache.WaitForCacheSync(ctx.Done(), informer.HasSynced))

	// Verify event was received
	select {
	case <-eventReceived:
		// Event received as expected
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive expected event")
	}
}

func TestNewFilteredSharedInformerFactory(t *testing.T) {
	client := newTestClientset()
	resyncPeriod := 30 * time.Second
	namespace := "test-namespace"
	tweakFunc := func(options *v1.ListOptions) {
		options.LabelSelector = "app=test"
	}

	factory := NewFilteredSharedInformerFactory(client, resyncPeriod, namespace, tweakFunc)

	assert.NotNil(t, factory)
	sif := factory.(*sharedInformerFactory)
	assert.Equal(t, namespace, sif.namespace)
	assert.NotNil(t, sif.tweakListOptions)
}

func TestSharedInformerFactory_MultipleInformerTypes(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Create multiple informer types
	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	_ = factory.Crd().V1beta1().NetworkPolicies().Informer()
	_ = factory.Crd().V1beta1().Tiers().Informer()
	_ = factory.Crd().V1alpha2().ExternalEntities().Informer()

	factory.Start(stopCh)

	sif := factory.(*sharedInformerFactory)
	assert.Equal(t, 4, len(sif.informers))
	assert.Equal(t, 4, len(sif.startedInformers))

	syncResults := factory.WaitForCacheSync(stopCh)
	assert.Len(t, syncResults, 4)
}

func TestSharedInformerFactory_ConcurrentAccess(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Simulate concurrent access to factory
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should only create one informer despite concurrent access
	sif := factory.(*sharedInformerFactory)
	assert.Equal(t, 1, len(sif.informers))
}

func TestSharedInformerFactory_AddInformersAfterStart(t *testing.T) {
	client := newTestClientset()
	factory := NewSharedInformerFactory(client, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Start with one informer
	_ = factory.Crd().V1beta1().ClusterNetworkPolicies().Informer()
	factory.Start(stopCh)

	sif := factory.(*sharedInformerFactory)
	assert.Len(t, sif.startedInformers, 1)

	// Add another informer after Start
	_ = factory.Crd().V1beta1().NetworkPolicies().Informer()

	// The new informer should not be started yet
	assert.Len(t, sif.startedInformers, 1)
	assert.Len(t, sif.informers, 2)

	// Call Start again to start the new informer
	factory.Start(stopCh)
	assert.Len(t, sif.startedInformers, 2)
}
