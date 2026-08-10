// Copyright 2026 Antrea Authors
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

package memberlistkeys

import (
	"bytes"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/apis"
)

// SecretWatcher watches the Secret which holds the memberlist keys and delivers them to a single
// handler. antrea-controller creates the Secret if it does not exist yet, so on a freshly installed
// cluster the first delivery can be delayed until the Secret appears.
type SecretWatcher struct {
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer

	// onKeys is invoked with the initial keys and with every subsequent change. It is registered by
	// Watch before the informer starts, so no update can be missed, and it is never invoked
	// concurrently, as informer event handlers run in a single goroutine.
	onKeys func(keys [][]byte)
	// keys holds the keys which were last delivered, so that updates to the Secret which do not
	// affect them are ignored. It is only accessed from handle, hence from a single goroutine.
	keys [][]byte
}

func NewSecretWatcher(client clientset.Interface, namespace string) *SecretWatcher {
	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		0, // no resync: we only care about actual changes
		informers.WithNamespace(namespace),
		// The field selector is not just an optimization: antrea-agent is only granted access to
		// this specific Secret (by resourceNames), and the API server derives the name of a LIST /
		// WATCH request from an exact match on metadata.name, which is what makes the request
		// authorized.
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("metadata.name=%s", apis.AntreaMemberlistSecretName)
		}),
	)
	w := &SecretWatcher{
		factory:  factory,
		informer: factory.Core().V1().Secrets().Informer(),
	}
	w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handle(obj) },
		UpdateFunc: func(_, obj interface{}) { w.handle(obj) },
		// A deleted Secret is ignored on purpose: the keys currently in use stay valid, and
		// antrea-controller recreates the Secret. Dropping the keys here would partition the
		// cluster for no good reason.
	})
	return w
}

// Watch registers onKeys and starts watching the Secret, until stopCh is closed. It does not
// block: onKeys is invoked from the watch goroutine with the current keys as soon as the Secret
// holds valid ones - which may be before Watch returns - and again after every change, always with
// at least one key. Watch must be called at most once.
func (w *SecretWatcher) Watch(stopCh <-chan struct{}, onKeys func(keys [][]byte)) {
	// No synchronization is needed: onKeys can only be read by handle, which the informer does not
	// invoke before it is started below.
	w.onKeys = onKeys
	w.factory.Start(stopCh)
}

func (w *SecretWatcher) handle(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	keys, err := ParseKeys(secret.Data[apis.MemberlistSecretKeysKey])
	if err != nil {
		klog.ErrorS(err, "Ignoring invalid memberlist keys", "secret", klog.KObj(secret))
		return
	}
	if slices.EqualFunc(w.keys, keys, bytes.Equal) {
		// Updates to the Secret which do not affect the keys are ignored, and must not be logged
		// either: they would otherwise repeat the messages below every time the Secret is written.
		return
	}
	first := w.keys == nil
	w.keys = keys

	if !first {
		klog.InfoS("Memberlist keys changed")
	}
	if len(keys) > 1 {
		// Support for rotating keys without partitioning the cluster is not implemented yet.
		klog.InfoS("Multiple memberlist keys found, only the first one is used", "count", len(keys))
	}
	w.onKeys(keys)
}
