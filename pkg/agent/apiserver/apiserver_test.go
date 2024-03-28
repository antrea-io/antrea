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

package apiserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/options"

	"antrea.io/antrea/pkg/agent/config"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	aqtest "antrea.io/antrea/pkg/agent/querier/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	"antrea.io/antrea/pkg/version"
)

type fakeAgentAPIServer struct {
	*agentAPIServer
	agentQuerier *aqtest.MockAgentQuerier
	npQuerier    *queriertest.MockAgentNetworkPolicyInfoQuerier
	ofClient     *oftest.MockClient
}

func newFakeAPIServer(t *testing.T) *fakeAgentAPIServer {
	tempDir := t.TempDir()
	kubeConfigPath := filepath.Join(tempDir, "kubeconfig")
	kubeConfigContent := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://localhost:56789
  name: cluster
contexts:
- context:
    cluster: cluster
  name: cluster
current-context: cluster
`
	if err := os.WriteFile(kubeConfigPath, []byte(kubeConfigContent), 0600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(tempDir, "token")
	version.Version = "v1.2.3"
	ctrl := gomock.NewController(t)
	agentQuerier := aqtest.NewMockAgentQuerier(ctrl)
	agentQuerier.EXPECT().GetNodeConfig().Return(&config.NodeConfig{OVSBridge: "br-int"})
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	ofClient := oftest.NewMockClient(ctrl)
	agentQuerier.EXPECT().GetOpenflowClient().AnyTimes().Return(ofClient)

	secureServing := options.NewSecureServingOptions().WithLoopback()
	secureServing.BindAddress = net.ParseIP("127.0.0.1")
	secureServing.BindPort = 10000
	authentication := options.NewDelegatingAuthenticationOptions()
	// InClusterLookup is skipped when testing, otherwise it would always fail as there is no real cluster.
	authentication.SkipInClusterLookup = true
	authorization := options.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths("/healthz", "/livez", "/readyz")
	apiServer, err := New(agentQuerier, npQuerier, nil, nil, secureServing, authentication, authorization, true, kubeConfigPath, tokenPath, true, true)
	require.NoError(t, err)
	fakeAPIServer := &fakeAgentAPIServer{
		agentAPIServer: apiServer,
		agentQuerier:   agentQuerier,
		npQuerier:      npQuerier,
		ofClient:       ofClient,
	}
	return fakeAPIServer
}

func TestAPIServerLivezCheck(t *testing.T) {
	tests := []struct {
		name                 string
		registerExpectations func(*fakeAgentAPIServer)
		expectedCode         int
		expectedBody         string
	}{
		{
			name: "ovs connected",
			registerExpectations: func(apiserver *fakeAgentAPIServer) {
				apiserver.ofClient.EXPECT().IsConnected().Return(true)
			},
			expectedCode: 200,
			expectedBody: "ok",
		},
		{
			name: "ovs disconnected",
			registerExpectations: func(apiserver *fakeAgentAPIServer) {
				apiserver.ofClient.EXPECT().IsConnected().Return(false)
			},
			expectedCode: 500,
			expectedBody: `[+]ping ok
[+]log ok
[-]ovs failed: reason withheld
[+]poststarthook/max-in-flight-filter ok
[+]poststarthook/storage-object-count-tracker-hook ok
[+]poststarthook/test-server-ready ok
livez check failed
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiserver := newFakeAPIServer(t)
			// we use this post-start hook to avoid a rare race condition where
			// getResponse(apiserver, "/healthz") is called while the healthz check is
			// still being installed. This happens when the server is queried before
			// PrepareRun() returns. Because post-start hooks are called much later, by
			// Run(), we ensure that we only query the server after checks have been
			// installed.
			var wg sync.WaitGroup
			wg.Add(1)
			apiserver.GenericAPIServer.AddPostStartHook(
				"test-server-ready",
				func(_ genericapiserver.PostStartHookContext) error {
					wg.Done()
					return nil
				},
			)
			stopCh := make(chan struct{})
			defer close(stopCh)
			go func() {
				apiserver.Run(stopCh)
			}()
			wg.Wait()

			// Wait for APIServer to be healthy.
			// After that, all built-in health checks will be guaranteed to return "ok".
			assert.Eventuallyf(t, func() bool {
				response := getResponse(apiserver, "/healthz")
				return response.Body.String() == "ok"
			}, 5*time.Second, 100*time.Millisecond, "APIServer didn't become healthy within 5 seconds")

			tt.registerExpectations(apiserver)
			response := getResponse(apiserver, "/livez")
			assert.Equal(t, tt.expectedBody, response.Body.String())
			assert.Equal(t, tt.expectedCode, response.Code)
		})
	}
}

func getResponse(apiserver *fakeAgentAPIServer, query string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(http.MethodGet, query, nil)
	recorder := httptest.NewRecorder()
	apiserver.GenericAPIServer.Handler.ServeHTTP(recorder, req)
	return recorder
}
