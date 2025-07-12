// Copyright 2022 Antrea Authors
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

package fake

import (
	"context"

	"k8s.io/client-go/testing"

<<<<<<< HEAD
	"antrea.io/antrea/apis/pkg/apis/controlplane/v1beta2"
=======
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
>>>>>>> origin/main
)

func (c *FakeSupportBundleCollections) UpdateStatus(ctx context.Context, name string, status *v1beta2.SupportBundleCollectionStatus) error {
	_, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(supportbundlecollectionsResource, "status", "", status), &v1beta2.SupportBundleCollectionStatus{})
	return err
}
