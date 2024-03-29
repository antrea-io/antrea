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

package featuregates

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/component-base/featuregate"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/features"
)

func TestGetStatus(t *testing.T) {
	assert.Equal(t, "Enabled", features.GetStatus(true))
	assert.Equal(t, "Disabled", features.GetStatus(false))
}

func TestHandleFunc(t *testing.T) {
	handler := HandleFunc()
	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)

	var resp []apis.FeatureGateResponse
	err = json.Unmarshal(recorder.Body.Bytes(), &resp)
	require.Nil(t, err)

	for _, v := range resp {
		df, ok := features.DefaultAntreaFeatureGates[featuregate.Feature(v.Name)]
		require.True(t, ok)
		assert.Equal(t, v.Status, features.GetStatus(df.Default))
		assert.Equal(t, v.Version, features.GetVersion(string(df.PreRelease)))
	}
}
