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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

// Server defines operations of an antctl server.
type Server interface {
	// Start runs the antctl server. When invoking this method, either AgentQuerier
	// or ControllerQuerier must be passed, because implementations need to
	// use the value of AgentMonitor and Controller monitor to tell out which
	// component the server is running in. A running server can be stopped by
	// closing the stopCh.
	Start(aq monitor.AgentQuerier, cq monitor.ControllerQuerier, stopCh <-chan struct{})
}

type localServer struct {
	// startOnce ensures the server could only be started one.
	startOnce sync.Once
	listener  net.Listener
}

// Start starts the server with the AgentQuerier or the ControllerQuerier passed.
// The server will do graceful stop whenever it receives from the stopCh. One server
// could only be run once.
func (s *localServer) Start(aq monitor.AgentQuerier, cq monitor.ControllerQuerier, stopCh <-chan struct{}) {
	s.startOnce.Do(func() {
		antctlMux := mux.NewPathRecorderMux("antctl-server")
		CommandList.applyToMux(antctlMux, aq, cq)
		server := &http.Server{Handler: antctlMux}
		// HTTP server graceful stop
		go func() {
			<-stopCh
			err := server.Shutdown(context.Background())
			if err != nil {
				klog.Errorf("Antctl server stopped with error: %v", err)
			} else {
				klog.Info("Antctl server stopped")
			}
		}()
		// Start the http server
		go func() {
			klog.Info("Starting antctl server")
			err := server.Serve(s.listener)
			if !errors.Is(err, http.ErrServerClosed) {
				klog.Fatalf("Antctl server stopped with error: %v", err)
			}
		}()
	})
}

// NewLocalServer creates an antctl server which listens on the local domain socket.
func NewLocalServer() (Server, error) {
	os.Remove(unixDomainSockAddr)
	ln, err := net.Listen("unix", unixDomainSockAddr)
	if err != nil {
		return nil, fmt.Errorf("error when creating antctl local server: %w", err)
	}
	return &localServer{listener: ln}, nil
}
