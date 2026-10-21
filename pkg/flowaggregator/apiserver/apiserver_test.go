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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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

// The tests below query each check on its own sub-path (e.g. /readyz/flowstreamservice-ready), which
// evaluates just that check. Unlike the aggregate /healthz, /livez and /readyz, it does not also
// depend on the generic apiserver's post-start hooks, so the apiserver does not have to be run for
// real. That would need a real listener, and it cannot be done inside a synctest bubble either:
// RunWithContext never returns when there is no SecureServingInfo, and healthz starts a
// wait.Forever goroutine of its own. A sub-path that is not registered is a 404, which is what lets
// these tests tell which of the three endpoints each check is installed on.

func TestInstallHealthChecks(t *testing.T) {
	tests := []struct {
		name  string
		ready bool
		live  bool
	}{
		{name: "serving", ready: true, live: true},
		// Starting, or draining during shutdown: not ready, but a restart would not help.
		{name: "not serving, not failed", ready: false, live: true},
		// Failed: only a restart recovers, so liveness fails as well.
		{name: "failed", ready: false, live: false},
	}
	statusOf := func(ok bool) int {
		if ok {
			return http.StatusOK
		}
		return http.StatusInternalServerError
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)
			faq.EXPECT().FlowStreamServiceReady().Return(tc.ready).AnyTimes()
			faq.EXPECT().FlowStreamServiceLive().Return(tc.live).AnyTimes()

			s := newTestGenericAPIServer(t)
			require.NoError(t, installHealthChecks(s, faq))
			s.PrepareRun()

			// The liveness check is on all three endpoints: healthz and livez because it is what they
			// exist for, readyz because a Pod that needs a restart cannot be ready.
			for _, path := range []string{"/healthz", "/livez", "/readyz"} {
				assert.Equal(t, statusOf(tc.live), getResponse(s, path+"/flowstreamservice-live").Code, path)
			}
			// The readiness check is on readyz only: livez must not fail while FlowStreamService is
			// merely starting or draining.
			assert.Equal(t, statusOf(tc.ready), getResponse(s, "/readyz/flowstreamservice-ready").Code)
			assert.Equal(t, http.StatusNotFound, getResponse(s, "/livez/flowstreamservice-ready").Code)
			assert.Equal(t, http.StatusNotFound, getResponse(s, "/healthz/flowstreamservice-ready").Code)
		})
	}
}

// TestInstallHealthChecksReflectsStateLive verifies that the checks are evaluated on every
// request rather than cached, and that a failure names the check responsible.
func TestInstallHealthChecksReflectsStateLive(t *testing.T) {
	ctrl := gomock.NewController(t)
	faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)
	var ready, live atomic.Bool
	ready.Store(true)
	live.Store(true)
	faq.EXPECT().FlowStreamServiceReady().DoAndReturn(ready.Load).AnyTimes()
	faq.EXPECT().FlowStreamServiceLive().DoAndReturn(live.Load).AnyTimes()

	s := newTestGenericAPIServer(t)
	require.NoError(t, installHealthChecks(s, faq))
	s.PrepareRun()

	response := getResponse(s, "/readyz/flowstreamservice-ready")
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "ok", response.Body.String())

	ready.Store(false)
	response = getResponse(s, "/readyz/flowstreamservice-ready")
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.Contains(t, response.Body.String(), "internal server error: FlowStreamService is not serving")
	assert.Equal(t, http.StatusOK, getResponse(s, "/livez/flowstreamservice-live").Code)

	live.Store(false)
	response = getResponse(s, "/livez/flowstreamservice-live")
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.Contains(t, response.Body.String(), "internal server error: FlowStreamService has failed")

	// A later successful start recovers it.
	ready.Store(true)
	live.Store(true)
	assert.Equal(t, http.StatusOK, getResponse(s, "/livez/flowstreamservice-live").Code)
	assert.Equal(t, http.StatusOK, getResponse(s, "/readyz/flowstreamservice-ready").Code)
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
