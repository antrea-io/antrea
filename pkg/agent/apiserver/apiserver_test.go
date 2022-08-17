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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	kubeConfigFile, err := os.CreateTemp("", "kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		kubeConfigFile.Close()
		os.Remove(kubeConfigFile.Name())
	}()
	if _, err := kubeConfigFile.Write([]byte(`
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
`)); err != nil {
		t.Fatal(err)
	}
	originalTokenPath := TokenPath
	tokenFile, err := os.CreateTemp("", "token")
	require.NoError(t, err)
	TokenPath = tokenFile.Name()
	defer func() {
		TokenPath = originalTokenPath
		tokenFile.Close()
		os.Remove(tokenFile.Name())
	}()
	version.Version = "v1.2.3"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
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
	apiServer, err := New(agentQuerier, npQuerier, nil, nil, secureServing, authentication, authorization, true, kubeConfigFile.Name(), true, true)
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
		name         string
		setupFunc    func(*fakeAgentAPIServer)
		expectedCode int
		expectedBody string
	}{
		{
			name: "ovs connected",
			setupFunc: func(apiserver *fakeAgentAPIServer) {
				apiserver.ofClient.EXPECT().IsConnected().Return(true)
			},
			expectedCode: 200,
			expectedBody: "ok",
		},
		{
			name: "ovs disconnected",
			setupFunc: func(apiserver *fakeAgentAPIServer) {
				apiserver.ofClient.EXPECT().IsConnected().Return(false)
			},
			expectedCode: 500,
			expectedBody: `[+]ping ok
[+]log ok
[-]ovs failed: reason withheld
[+]poststarthook/max-in-flight-filter ok
livez check failed
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiserver := newFakeAPIServer(t)
			stopCh := make(chan struct{})
			defer close(stopCh)
			go func() {
				apiserver.Run(stopCh)
			}()
			// Wait for APIServer to be healthy so checks installed by default are ensured ok.
			assert.Eventuallyf(t, func() bool {
				response := getResponse(apiserver, "/healthz")
				return response.Body.String() == "ok"
			}, time.Second*5, time.Millisecond*100, "APIServer didn't become health in 5 seconds")

			tt.setupFunc(apiserver)
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
