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

package e2e

import (
	"testing"

	openapi_v2 "github.com/google/gnostic-models/openapiv2"
	"github.com/stretchr/testify/require"
	"k8s.io/kube-openapi/pkg/util/proto"
)

// TestOpenAPISchema validates the OpenAPI v2 schema served by the Kubernetes
// API server. The raw schema is fetched, parsed into an OpenAPI v2 document,
// and converted to proto models. The proto.NewOpenAPIData step resolves all
// $ref pointers and will return an error if any reference points to a
// non-existent definition (e.g. because of incorrect openapi-model-package
// directives causing a mismatch between definition keys and references).
func TestOpenAPISchema(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	raw, err := data.clientset.Discovery().RESTClient().Get().AbsPath("/openapi/v2").DoRaw(t.Context())
	require.NoError(t, err, "failed to fetch OpenAPI v2 schema")

	document, err := openapi_v2.ParseDocument(raw)
	require.NoError(t, err, "failed to parse OpenAPI v2 document")

	_, err = proto.NewOpenAPIData(document)
	require.NoError(t, err, "failed to build proto models from OpenAPI document")
}
