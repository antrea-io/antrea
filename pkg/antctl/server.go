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
	apiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/klog"
)

// StartServer tries to start a CLI server configured by the options. It returns a channel to tell whether the server stopped
// and the error the CLI server encountered.
func StartServer(opts *ServerOptions, stopCh <-chan struct{}) (<-chan struct{}, error) {
	secureServing := new(apiserver.SecureServingInfo)
	authentication := new(apiserver.AuthenticationInfo)
	authorization := new(apiserver.AuthorizationInfo)
	router := mux.NewPathRecorderMux("antctl")

	err := opts.SecureServing.ApplyTo(&secureServing, nil)
	if err != nil {
		return nil, err
	}

	err = opts.Authorization.ApplyTo(authorization)
	if err != nil {
		return nil, err
	}

	err = opts.Authentication.ApplyTo(authentication, secureServing, nil)
	if err != nil {
		return nil, err
	}

	opts.CommandBundle.ApplyToRouter(router, opts.AgentQuerier, opts.ControllerQuerier)

	klog.Info("Starting antctl server")
	stoppedCh, err := secureServing.Serve(opts.DelegateAA(router, authentication.Authenticator, authorization.Authorizer), 0, stopCh)
	if err != nil {
		return nil, err
	}

	return stoppedCh, nil
}
