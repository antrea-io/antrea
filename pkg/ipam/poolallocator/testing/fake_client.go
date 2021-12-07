// Copyright 2021 Antrea Authors
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

package testing

import (
	"sync"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

// Simple client is not sufficient for pool allocator testing,
// since pool allocator relies on both crd client and pool informer
// to work in sync. This client extension mimics the real client in
// conflict handling functionality - pool update will return conflict
// error unless ResourceVersion for the updated pool reflect the version
// stored in the client.
type IPPoolClientset struct {
	fakeversioned.Clientset
	// store latest ResourceVersion for given pool
	poolVersion sync.Map
	watcher     *watch.RaceFreeFakeWatcher
}

func (c *IPPoolClientset) InitPool(pool *crdv1a2.IPPool) {
	pool.ResourceVersion = uuid.New().String()
	c.poolVersion.Store(pool.Name, pool.ResourceVersion)

	c.watcher.Add(pool)
}

func NewIPPoolClient() *IPPoolClientset {

	crdClient := &IPPoolClientset{watcher: watch.NewRaceFreeFake()}
	// map needs to be populated in order to persist across threads
	crdClient.poolVersion.Store("placeholder", nil)

	crdClient.AddReactor("update", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updatedPool := action.(k8stesting.UpdateAction).GetObject().(*crdv1a2.IPPool)
		obj, exists := crdClient.poolVersion.Load(updatedPool.Name)
		if !exists {
			return false, nil, nil
		}
		storedPoolVersion := obj.(string)
		if storedPoolVersion != updatedPool.ResourceVersion {
			return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonConflict, Message: "pool status update conflict"}}
		}

		updatedPool.ResourceVersion = uuid.New().String()
		crdClient.poolVersion.Store(updatedPool.Name, updatedPool.ResourceVersion)
		crdClient.watcher.Modify(updatedPool)
		return true, updatedPool, nil
	})

	crdClient.AddWatchReactor("ippools", k8stesting.DefaultWatchReactor(crdClient.watcher, nil))

	return crdClient
}
