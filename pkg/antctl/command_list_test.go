// Copyright 2019 Antrea Authors
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

package antctl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/mux"

	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

type testHandlerFactory struct{}

func (t *testHandlerFactory) Handler(_ monitor.AgentQuerier, _ monitor.ControllerQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		fmt.Fprint(w, "test")
	}
}

type testResponse struct {
	Label string `json:"label" antctl:"key"`
	Value uint64 `json:"value"`
}

var testCommandList = &commandList{
	definitions: []commandDefinition{
		{
			Use:                 "test",
			Short:               "test short description ${component}",
			Long:                "test description ${component}",
			HandlerFactory:      new(testHandlerFactory),
			TransformedResponse: reflect.TypeOf(testResponse{}),
			Agent:               true,
			Controller:          true,
			GroupVersion: &schema.GroupVersion{
				Group:   "test-clusterinformation.antrea.tanzu.vmware.com",
				Version: "v1",
			},
		},
	},
	codec: scheme.Codecs,
}

func TestCommandListApplyToCommand(t *testing.T) {
	testRoot := new(cobra.Command)
	testRoot.Short = "The component is ${component}"
	testRoot.Long = "The component is ${component}"
	testCommandList.ApplyToRootCommand(testRoot, true, false)
	// sub-commands should be attached
	assert.True(t, testRoot.HasSubCommands())
	// render should work as expected
	assert.Contains(t, testRoot.Short, "The component is agent")
	assert.Contains(t, testRoot.Long, "The component is agent")
}

// TestParseCommandList ensures the commandList could be correctly parsed.
func TestParseCommandList(t *testing.T) {
	r := mux.NewPathRecorderMux("")
	assert.Len(t, testCommandList.validate(), 0)
	testCommandList.applyToMux(r, nil, nil)

	ts := httptest.NewServer(r)
	defer ts.Close()

	testcases := map[string]struct {
		path       string
		statusCode int
	}{
		"ExistPath": {
			path:       "/apis/" + testCommandList.definitions[0].GroupVersion.String() + "/test",
			statusCode: http.StatusOK,
		},
		"NotExistPath": {
			path:       "test",
			statusCode: http.StatusNotFound,
		},
	}

	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			reqPath, err := url.Parse(ts.URL)
			assert.Nil(t, err)
			reqPath.Path = tc.path
			resp, err := ts.Client().Get(reqPath.String())
			assert.Nil(t, err, k)

			defer resp.Body.Close()
			assert.Equal(t, tc.statusCode, resp.StatusCode, fmt.Sprintf("case %s %s", k, reqPath))
		})
	}
}
