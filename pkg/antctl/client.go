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

	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
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
			err = fmt.Errorf("Unable to resolve in-cluster configuration: %v. Please specify the kubeconfig file", err)
		}
	} else {
		kubeconfig, err = clientcmd.BuildConfigFromFlags("", opt.kubeconfig)
	}
	if err != nil {
		return nil, err
	}
	kubeconfig.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: c.codec}
	return kubeconfig, nil
}

func (c *client) request(opt *requestOption) (io.Reader, error) {
	var e *endpoint
	if runtimeComponent == componentAgent {
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
	if runtimeComponent == componentAgent {
		kubeconfig.Insecure = true
		kubeconfig.CAFile = ""
		kubeconfig.Host = net.JoinHostPort("127.0.0.1", fmt.Sprint(apiserver.Port))
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
	result := getter.Do()
	if result.Error() != nil {
		return nil, generateMessage(opt, result)
	}
	raw, err := result.Raw()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}

func (c *client) resourceRequest(e *resourceEndpoint, opt *requestOption) (io.Reader, error) {
	kubeconfig, err := c.resolveKubeconfig(opt)
	if err != nil {
		return nil, err
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
