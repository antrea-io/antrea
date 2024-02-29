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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/apis"
)

// requestOption describes options to issue requests.
type requestOption struct {
	commandDefinition *commandDefinition
	// kubeconfig is the path to the config file for kubectl.
	kubeconfig string
	// args are the parameters of the ongoing resourceRequest.
	args map[string]string
	// timeout specifies a time limit for requests made by the client. The timeout
	// duration includes connection setup, all redirects, and reading of the
	// response body.
	timeout time.Duration
	// server is the address and port of the APIServer specified by user explicitly.
	// If not set, antctl will connect to 127.0.0.1:10350 in agent mode, and will
	// connect to the server set in kubeconfig in controller mode.
	// It set, it takes precedence over the above default endpoints.
	server string
}

type AntctlClient interface {
	request(opt *requestOption) (io.Reader, error)
}

// client issues requests to endpoints.
type client struct {
	// codec is the CodecFactory for this command, it is needed for remote accessing.
	codec serializer.CodecFactory
}

func newClient(codec serializer.CodecFactory) AntctlClient {
	return &client{codec: codec}
}

// resolveKubeconfig tries to load the kubeconfig specified in the requestOption.
// It will return error if the stating of the file failed or the kubeconfig is malformed.
// If the default kubeconfig not exists, it will try to use an in-cluster config.
func (c *client) resolveKubeconfig(opt *requestOption) (*rest.Config, error) {
	var kubeconfig *rest.Config
	if runtime.InPod {
		kubeconfig = &rest.Config{}
		kubeconfig.Insecure = true
		kubeconfig.CAFile = ""
		kubeconfig.CAData = nil
		kubeconfig.BearerTokenFile = apis.APIServerLoopbackTokenPath
		if runtime.Mode == runtime.ModeAgent {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apis.AntreaAgentAPIPort))
		} else if runtime.Mode == runtime.ModeController {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apis.AntreaControllerAPIPort))
		} else if runtime.Mode == runtime.ModeFlowAggregator {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apis.FlowAggregatorAPIPort))
		}
	} else {
		var err error
		if kubeconfig, err = runtime.ResolveKubeconfig(opt.kubeconfig); err != nil {
			return nil, err
		}
	}
	kubeconfig.NegotiatedSerializer = c.codec
	return kubeconfig, nil
}

func (c *client) request(opt *requestOption) (io.Reader, error) {
	var e *endpoint
	if runtime.Mode == runtime.ModeAgent {
		e = opt.commandDefinition.agentEndpoint
	} else if runtime.Mode == runtime.ModeFlowAggregator {
		e = opt.commandDefinition.flowAggregatorEndpoint
	} else {
		e = opt.commandDefinition.controllerEndpoint
	}
	if e.resourceEndpoint != nil {
		return c.resourceRequest(e.resourceEndpoint, opt)
	}
	return c.nonResourceRequest(e.nonResourceEndpoint, opt)
}

func (c *client) nonResourceRequest(e *nonResourceEndpoint, opt *requestOption) (io.Reader, error) {
	kubeconfig, err := c.resolveKubeconfig(opt)
	if err != nil {
		return nil, err
	}
	if opt.server != "" {
		kubeconfig.Host = opt.server
	}
	restClient, err := rest.UnversionedRESTClientFor(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create rest client: %w", err)
	}
	u := url.URL{Path: e.path}
	q := u.Query()
	for k, v := range opt.args {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	getter := restClient.Get().RequestURI(u.RequestURI()).Timeout(opt.timeout)
	result, err := getter.DoRaw(context.TODO())
	if err != nil {
		statusErr, ok := err.(*errors.StatusError)
		if !ok {
			return nil, err
		}
		return nil, generateMessage(opt.commandDefinition, opt.args, false /* isResourceRequest */, statusErr)
	}
	return bytes.NewReader(result), nil
}

func (c *client) resourceRequest(e *resourceEndpoint, opt *requestOption) (io.Reader, error) {
	kubeconfig, err := c.resolveKubeconfig(opt)
	if err != nil {
		return nil, err
	}
	if opt.server != "" {
		kubeconfig.Host = opt.server
	}
	gv := e.groupVersionResource.GroupVersion()
	kubeconfig.GroupVersion = &gv
	kubeconfig.APIPath = "/apis"

	restClient, err := rest.RESTClientFor(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create rest client: %w", err)
	}
	// If timeout is zero, there will be no timeout.
	restClient.Client.Timeout = opt.timeout

	var restRequest *rest.Request
	if e.restMethod == restGet {
		restRequest = restClient.Get()
	} else if e.restMethod == restPost {
		restRequest = restClient.Post()
	}

	restRequest = restRequest.
		NamespaceIfScoped(opt.args["namespace"], e.namespaced).
		Resource(e.groupVersionResource.Resource)

	if len(e.resourceName) != 0 {
		restRequest = restRequest.Name(e.resourceName)
	} else if name, ok := opt.args["name"]; ok {
		restRequest = restRequest.Name(name)
	}

	for arg, val := range opt.args {
		if arg != "name" && arg != "namespace" {
			restRequest = restRequest.Param(arg, val)
		}
	}

	if e.parameterTransform != nil {
		obj, err := e.parameterTransform(opt.args)
		if err != nil {
			return nil, err
		}
		restRequest = restRequest.Body(obj)
	}

	result := restRequest.Do(context.TODO())
	if result.Error() != nil {
		return nil, generateMessage(opt.commandDefinition, opt.args, true /* isResourceRequest */, result.Error())
	}
	raw, err := result.Raw()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}
