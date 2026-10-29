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

package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	fakeclientset "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
)

func TestAgentPublicationCancel(t *testing.T) {
	entered, canceled, releaseHandler := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(releaseHandler)
	info := &v1beta1.AntreaAgentInfo{
		TypeMeta:   metav1.TypeMeta{APIVersion: "crd.antrea.io/v1beta1", Kind: "AntreaAgentInfo"},
		ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/crd.antrea.io/v1beta1/antreaagentinfos/testAgentCRD":
			response := info.DeepCopy()
			if r.Method == http.MethodPut {
				if err := json.NewDecoder(r.Body).Decode(response); err != nil {
					t.Errorf("decode published AgentInfo: %v", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-releaseHandler:
				}
				return
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("encode AgentInfo: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := clientset.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)
	provider := &testNodeConfigProvider{report: &v1beta1.AntreaNodeConfigAgentStatus{ConfigName: "config-a", ConfigUID: "config-a-uid"}}
	monitor := newAgentMonitor(fakeclientset.NewSimpleClientset(), t)
	monitor.SetNodeConfigStatusProvider(provider)
	monitor.client = client
	stopCh, done := make(chan struct{}), make(chan struct{})
	go func() {
		monitor.Run(stopCh)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(stopCh)
		t.Fatal("monitor did not begin the AgentInfo update")
	}
	close(stopCh)
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("stopping the monitor did not cancel its outstanding AgentInfo update")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not return after stopping")
	}
}
