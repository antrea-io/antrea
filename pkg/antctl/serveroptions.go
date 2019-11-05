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
	"net"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	apioptions "k8s.io/apiserver/pkg/server/options"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

const (
	controllerPort = 1443
	agentPort      = 2443
)

// ServerOptions defines all options of a cli server.
type ServerOptions struct {
	AgentQuerier      monitor.AgentQuerier
	ControllerQuerier monitor.ControllerQuerier
	SecureServing     *apioptions.SecureServingOptionsWithLoopback
	Authentication    *apioptions.DelegatingAuthenticationOptions
	Authorization     *apioptions.DelegatingAuthorizationOptions
	CommandBundle     *CommandBundle
	Codec             serializer.CodecFactory
}

func newDefaultServerOptions(bundle *CommandBundle, aq monitor.AgentQuerier, cq monitor.ControllerQuerier, port int) (*ServerOptions, error) {
	o := &ServerOptions{
		SecureServing:     apioptions.NewSecureServingOptions().WithLoopback(),
		Authentication:    apioptions.NewDelegatingAuthenticationOptions(),
		Authorization:     apioptions.NewDelegatingAuthorizationOptions(),
		AgentQuerier:      aq,
		ControllerQuerier: cq,
		CommandBundle:     bundle,
		Codec:             bundle.Codec,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	o.SecureServing.BindPort = port
	o.SecureServing.Listener = ln

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	err = o.SecureServing.MaybeDefaultWithSelfSignedCerts(hostname, nil, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}

	o.Authentication.TolerateInClusterLookupFailure = true
	o.Authentication.RemoteKubeConfigFileOptional = false
	o.Authorization.RemoteKubeConfigFileOptional = false

	return o, nil
}

// NewControllerServerOptions creates an options of a server for remote access.
func NewControllerServerOptions(bundle *CommandBundle, cq monitor.ControllerQuerier) (*ServerOptions, error) {
	opts, err := newDefaultServerOptions(bundle, nil, cq, controllerPort)
	if err != nil {
		return nil, errors.Wrap(err, "error creating controller antctl server options")
	}
	return opts, nil
}

// NewAgentServerOptions creates an options of a server for local access.
func NewAgentServerOptions(bundle *CommandBundle, ag monitor.AgentQuerier) (*ServerOptions, error) {
	opts, err := newDefaultServerOptions(bundle, ag, nil, agentPort)
	if err != nil {
		return nil, errors.Wrap(err, "error creating agent antctl server options")
	}
	return opts, nil
}

// Validate checks if the options is a valid one.
func (o *ServerOptions) Validate() []error {
	var errs []error
	errs = append(errs, o.SecureServing.Validate()...)
	errs = append(errs, o.Authentication.Validate()...)
	errs = append(errs, o.Authorization.Validate()...)
	errs = append(errs, o.CommandBundle.Validate()...)
	return errs
}

// DelegateAA add kubernetes AA delegation to the router.
func (o *ServerOptions) DelegateAA(h http.Handler, authn authenticator.Request, authz authorizer.Authorizer) http.Handler {
	resolver := new(request.RequestInfoFactory)

	h = filters.WithAuthorization(h, authz, o.Codec)
	h = filters.WithAuthentication(h, authn, filters.Unauthorized(o.Codec, false), nil)
	h = filters.WithRequestInfo(h, resolver)
	h = genericfilters.WithPanicRecovery(h)

	return h
}
