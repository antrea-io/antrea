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

package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	genericapiserver "k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
	basecompatibility "k8s.io/component-base/compatibility"
	netutils "k8s.io/utils/net"

	queriertest "antrea.io/antrea/v2/pkg/flowaggregator/querier/testing"
)

// newTestGenericAPIServer builds a minimal, unstarted GenericAPIServer, sufficient to register
// and exercise health checks via Handler.ServeHTTP directly, without binding any real listener
// (that only happens in Run/RunWithContext) and without going through this package's own New,
// which writes a loopback token to a hardcoded system path unsuitable for unit tests.
func newTestGenericAPIServer(t *testing.T) *genericapiserver.GenericAPIServer {
	cfg := genericapiserver.NewConfig(codecs)
	cfg.ExternalAddress = "192.168.10.4:443"
	cfg.PublicAddress = netutils.ParseIPSloppy("192.168.10.4")
	cfg.LoopbackClientConfig = &restclient.Config{}
	cfg.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString("", "", "")
	s, err := cfg.Complete(nil).New(Name, genericapiserver.NewEmptyDelegate())
	require.NoError(t, err)
	return s
}

func getResponse(s *genericapiserver.GenericAPIServer, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	s.Handler.ServeHTTP(recorder, req)
	return recorder
}

func TestInstallHealthChecks(t *testing.T) {
	ctrl := gomock.NewController(t)
	faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)
	var ready atomic.Bool
	ready.Store(true)
	faq.EXPECT().FlowStreamServiceReady().DoAndReturn(ready.Load).AnyTimes()

	s := newTestGenericAPIServer(t)
	require.NoError(t, installHealthChecks(s, faq))

	// SecureServingInfo is nil here (this test never binds a real listener), so
	// RunWithContext only runs the post-start hooks; leaving it running for the duration of the
	// test lets those hooks (which /healthz also checks) actually complete.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = s.PrepareRun().RunWithContext(ctx)
	}()

	// Wait for the server to become healthy with FlowStreamService reported ready, so that the
	// subsequent, deterministic checks below aren't confused by post-start hooks still pending.
	require.Eventuallyf(t, func() bool {
		response := getResponse(s, "/healthz")
		return response.Code == http.StatusOK && response.Body.String() == "ok"
	}, 5*time.Second, 100*time.Millisecond, "APIServer didn't become healthy within 5 seconds")

	// Now that the server is known-healthy, flipping FlowStreamService's reported state must be
	// reflected immediately on the very next request: the check is pull-based, not cached.
	ready.Store(false)
	response := getResponse(s, "/healthz")
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.Contains(t, response.Body.String(), "[-]flowstreamservice failed: reason withheld")

	ready.Store(true)
	response = getResponse(s, "/healthz")
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "ok", response.Body.String())
}

func TestInstallHealthChecksAlreadyInstalled(t *testing.T) {
	ctrl := gomock.NewController(t)
	faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)

	s := newTestGenericAPIServer(t)
	require.NoError(t, installHealthChecks(s, faq))
	s.PrepareRun()

	// Once PrepareRun has installed the actual handlers, adding further checks must fail: this is
	// exactly why installHealthChecks must run before PrepareRun, as documented on the function.
	assert.Error(t, installHealthChecks(s, faq))
}
