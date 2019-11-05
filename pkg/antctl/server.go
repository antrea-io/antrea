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
	"net/http"

	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/klog"
)

// StartLocalServer tries to start a CLI server configured by the options. It returns a channel to tell invoker whether the
// server stopped and the error the CLI server encountered.
func StartLocalServer(opts *ServerOptions, stopCh <-chan struct{}) <-chan struct{} {
	router := mux.NewPathRecorderMux("antctl")
	opts.CommandBundle.ApplyToRouter(router, opts.AgentQuerier, opts.ControllerQuerier)
	server := &http.Server{Handler: router}
	stoppedCh := make(chan struct{})

	// Do http server graceful stop
	go func() {
		<-stopCh
		server.Shutdown(context.Background())
	}()

	// Run the http server
	go func() {
		klog.Info("Starting antctl server")
		server.Serve(opts.Listener)
		close(stoppedCh)
	}()

	return stoppedCh
}
