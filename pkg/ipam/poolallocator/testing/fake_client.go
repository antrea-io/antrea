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
	k8stesting "k8s.io/client-go/testing"

	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
)

// IPPoolClientset extends the generated fake clientset to simulate optimistic
// concurrency for IPPool updates: an update is rejected with a conflict error
// unless the ResourceVersion in the request matches what is stored.
// Use NewIPPoolClient to construct it; use the standard Create API to register
// pools (the create reactor assigns ResourceVersion automatically).
type IPPoolClientset struct {
	*fakeversioned.Clientset
	// store latest ResourceVersion for given pool
	poolVersion sync.Map
}

func NewIPPoolClient() *IPPoolClientset {
	// NewSimpleClientset provides a working object tracker that handles list,
	// get, create, and update for all resource types via its default reactors.
	// The tracker also sends watch events (Added/Modified) so no custom watcher
	// is needed.
	crdClient := &IPPoolClientset{
		Clientset:   fakeversioned.NewSimpleClientset(),
		poolVersion: sync.Map{},
	}

	// Intercept create to assign ResourceVersion and register it for conflict
	// detection, then let the tracker handle the actual storage and watch event.
	crdClient.PrependReactor("create", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pool := action.(k8stesting.CreateAction).GetObject().(*crdv1b1.IPPool)
		pool.ResourceVersion = uuid.New().String()
		crdClient.poolVersion.Store(pool.Name, pool.ResourceVersion)
		return false, pool, nil
	})

	// Intercept update to enforce optimistic concurrency, then let the tracker
	// handle the actual storage and watch event.
	crdClient.PrependReactor("update", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updatedPool := action.(k8stesting.UpdateAction).GetObject().(*crdv1b1.IPPool)
		obj, exists := crdClient.poolVersion.Load(updatedPool.Name)
		if !exists {
			return false, nil, nil
		}
		if obj.(string) != updatedPool.ResourceVersion {
			return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonConflict, Message: "pool status update conflict"}}
		}
		updatedPool.ResourceVersion = uuid.New().String()
		crdClient.poolVersion.Store(updatedPool.Name, updatedPool.ResourceVersion)
		return false, updatedPool, nil
	})

	return crdClient
}
