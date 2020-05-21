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
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	agentapiserver "github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apis"
	controllerapiserver "github.com/vmware-tanzu/antrea/pkg/apiserver"
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

// client issues requests to endpoints.
type client struct {
	// codec is the CodecFactory for this command, it is needed for remote accessing.
	codec serializer.CodecFactory
}

// resolveKubeconfig tries to load the kubeconfig specified in the requestOption.
// It will return error if the stating of the file failed or the kubeconfig is malformed.
// If the default kubeconfig not exists, it will try to use an in-cluster config.
func (c *client) resolveKubeconfig(opt *requestOption) (*rest.Config, error) {
	var err error
	var kubeconfig *rest.Config
	if _, err = os.Stat(opt.kubeconfig); opt.kubeconfig == clientcmd.RecommendedHomeFile && os.IsNotExist(err) {
		kubeconfig, err = rest.InClusterConfig()
		if err != nil {
			err = fmt.Errorf("unable to resolve in-cluster configuration: %v. Please specify the kubeconfig file", err)
		}
	} else {
		kubeconfig, err = clientcmd.BuildConfigFromFlags("", opt.kubeconfig)
	}
	if err != nil {
		return nil, err
	}
	kubeconfig.NegotiatedSerializer = c.codec
	if inPod {
		kubeconfig.Insecure = true
		kubeconfig.CAFile = ""
		kubeconfig.CAData = nil
		if runtimeMode == ModeAgent {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apis.AntreaAgentAPIPort))
			kubeconfig.BearerTokenFile = agentapiserver.TokenPath
		} else if runtimeMode == ModeController {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apis.AntreaControllerAPIPort))
			kubeconfig.BearerTokenFile = controllerapiserver.TokenPath
		}
	}
	return kubeconfig, nil
}

func (c *client) request(opt *requestOption) (io.Reader, error) {
	var e *endpoint
	if runtimeMode == ModeAgent {
		e = opt.commandDefinition.agentEndpoint
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
	result, err := getter.DoRaw()
	if err != nil {
		statusErr, ok := err.(*errors.StatusError)
		if !ok {
			return nil, err
		}
		return nil, generateMessageForStatusErr(opt.commandDefinition, opt.args, statusErr)
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
	kubeconfig.APIPath = genericapiserver.APIGroupPrefix

	restClient, err := rest.RESTClientFor(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create rest client: %w", err)
	}
	// If timeout is zero, there will be no timeout.
	restClient.Client.Timeout = opt.timeout

	resGetter := restClient.Get().
		NamespaceIfScoped(opt.args["namespace"], e.namespaced).
		Resource(e.groupVersionResource.Resource)

	if len(e.resourceName) != 0 {
		resGetter = resGetter.Name(e.resourceName)
	} else if name, ok := opt.args["name"]; ok {
		resGetter = resGetter.Name(name)
	}

	for arg, val := range opt.args {
		if arg != "name" && arg != "namespace" {
			resGetter = resGetter.Param(arg, val)
		}
	}
	result := resGetter.Do()
	if result.Error() != nil {
		return nil, generateMessage(opt, result)
	}
	raw, err := result.Raw()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}
