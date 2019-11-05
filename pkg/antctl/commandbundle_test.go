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
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/mux"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

type testHandlerFactory struct{}

func (t *testHandlerFactory) Handler(agentQuerier monitor.AgentQuerier, controllerQuerier monitor.ControllerQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		fmt.Fprint(w, "test")
	}
}

type testResponse struct {
	Label string `json:"label" antctl:"key"`
	Value uint64 `json:"value"`
}

var TestBundle = &CommandBundle{
	CommandOptions: []CommandOption{
		{
			Use:            "test",
			Short:          "test short description ${component}",
			Long:           "test description ${component}",
			HandlerFactory: new(testHandlerFactory),
			ResponseStruct: new(testResponse),
			Agent:          true,
			Controller:     true,
		},
	},
	GroupVersion: &schema.GroupVersion{
		Group:   "test-antctl.antrea.io",
		Version: "v1",
	},
}

func TestCommandBundleApplyToCommand(t *testing.T) {
	testRoot := new(cobra.Command)
	testRoot.Short = "The component is ${component}"
	testRoot.Long = "The component is ${component}"
	TestBundle.ApplyToCommand(testRoot, new(Client), true)
	// sub-command should be attached
	assert.True(t, testRoot.HasSubCommands())
	// render should work
	assert.Contains(t, testRoot.Short, "The component is agent")
	assert.Contains(t, testRoot.Long, "The component is agent")
}

func TestParseBundle(t *testing.T) {
	r := mux.NewPathRecorderMux("")
	assert.Len(t, TestBundle.Validate(), 0)
	TestBundle.ApplyToRouter(r, nil, nil)

	ts := httptest.NewServer(r)
	defer ts.Close()

	testcases := map[string]struct {
		path       string
		statusCode int
	}{
		"Discovery": {
			path:       TestBundle.APIPrefix(),
			statusCode: http.StatusOK,
		},
		"ExistPath": {
			path:       path.Join(TestBundle.APIPrefix(), "test"),
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
