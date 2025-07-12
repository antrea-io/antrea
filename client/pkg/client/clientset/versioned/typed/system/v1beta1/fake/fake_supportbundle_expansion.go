// Copyright 2023 Antrea Authors
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
	"bytes"
	"context"
	"io"

	"k8s.io/client-go/testing"
)

func (c *FakeSupportBundles) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	// This should record the action correctly.
	// Reactors are not supported here, since we do not return a runtime.Object.
	_, err := c.Fake.
		Invokes(testing.NewRootGetSubresourceAction(supportbundlesResource, "download", name), nil)
	if err != nil {
		return nil, err
	}
	// This seems like a good default to return.
	return io.NopCloser(bytes.NewReader(nil)), nil
}
