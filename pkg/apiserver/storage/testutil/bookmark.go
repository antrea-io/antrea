// Copyright 2026 Antrea Authors
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

// Package testutil provides shared helpers for tests that assert on the events emitted by the
// in-memory watch storage.
package testutil

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// ExpectedInitBookmark returns the bookmark event that the storage emits to mark the end of the
// initial set of events for a watch: the bookmark object carries the given resourceVersion and the
// "k8s.io/initial-events-end" annotation required by the Kubernetes watch-list contract.
//
// The provided object is deep-copied before being mutated, so callers can pass a shared empty
// object without risking accidental shared state, and only the initial-events-end annotation is
// added (any existing annotations are preserved). It accepts testing.TB so it can be used from
// tests and benchmarks alike.
func ExpectedInitBookmark(tb testing.TB, obj runtime.Object, resourceVersion string) watch.Event {
	tb.Helper()
	obj = obj.DeepCopyObject()
	accessor, err := meta.Accessor(obj)
	if err != nil {
		tb.Fatalf("Failed to access bookmark object metadata: %v", err)
	}
	accessor.SetResourceVersion(resourceVersion)
	annotations := accessor.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[metav1.InitialEventsAnnotationKey] = "true"
	accessor.SetAnnotations(annotations)
	return watch.Event{Type: watch.Bookmark, Object: obj}
}
