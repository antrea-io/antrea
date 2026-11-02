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

package v1beta2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestNodeNameFieldLabel checks that the API server accepts the field selector with which the Antrea Agents watch
// the resources that are sent to their Node.
func TestNodeNameFieldLabel(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))
	for _, kind := range []string{"AppliedToGroup", "AddressGroup", "NetworkPolicy", "EgressGroup", "EgressAddressGroup",
		"SupportBundleCollection"} {
		label, value, err := scheme.ConvertFieldLabel(SchemeGroupVersion.WithKind(kind), "nodeName", "node1")
		if assert.NoError(t, err, "kind %s", kind) {
			assert.Equal(t, "nodeName", label)
			assert.Equal(t, "node1", value)
		}
		_, _, err = scheme.ConvertFieldLabel(SchemeGroupVersion.WithKind(kind), "spec.foo", "bar")
		assert.Error(t, err, "kind %s", kind)
	}
}
