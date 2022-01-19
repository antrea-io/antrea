// Copyright 2022 Antrea Authors
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/addressgroup"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/appliedtogroup"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/featuregates"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/networkpolicy"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovsflows"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovstracing"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	agentquerier "antrea.io/antrea/pkg/agent/querier"
	systeminstall "antrea.io/antrea/pkg/apis/system/install"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	"antrea.io/antrea/pkg/apiserver/handlers/loglevel"
	"antrea.io/antrea/pkg/apiserver/registry/system/supportbundle"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
)

const Name = "antrea-agent-api"

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
	// #nosec G101: false positive triggered by variable name which includes "token"
	TokenPath = "/var/run/antrea/apiserver/loopback-client-token"
)

func init() {
	systeminstall.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
}

type agentAPIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

func (s *agentAPIServer) Run(stopCh <-chan struct{}) error {
	return s.GenericAPIServer.PrepareRun().Run(stopCh)
}

func installHandlers(aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, s *genericapiserver.GenericAPIServer) {
	s.Handler.NonGoRestfulMux.HandleFunc("/loglevel", loglevel.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/featuregates", featuregates.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/agentinfo", agentinfo.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/podinterfaces", podinterface.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/networkpolicies", networkpolicy.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/appliedtogroups", appliedtogroup.HandleFunc(npq))
	s.Handler.NonGoRestfulMux.HandleFunc("/addressgroups", addressgroup.HandleFunc(npq))
	s.Handler.NonGoRestfulMux.HandleFunc("/ovsflows", ovsflows.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/ovstracing", ovstracing.HandleFunc(aq))
}

func installAPIGroup(s *genericapiserver.GenericAPIServer, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier) error {
	systemGroup := genericapiserver.NewDefaultAPIGroupInfo(systemv1beta1.GroupName, scheme, metav1.ParameterCodec, codecs)
	systemStorage := map[string]rest.Storage{}
	supportBundleStorage := supportbundle.NewAgentStorage(ovsctl.NewClient(aq.GetNodeConfig().OVSBridge), aq, npq)
	systemStorage["supportbundles"] = supportBundleStorage.SupportBundle
	systemStorage["supportbundles/download"] = supportBundleStorage.Download
	systemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage
	return s.InstallAPIGroup(&systemGroup)
}

// New creates an APIServer for running in antrea agent.
func New(aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, bindPort int,
	enableMetrics bool, kubeconfig string, cipherSuites []uint16, tlsMinVersion uint16) (*agentAPIServer, error) {
	cfg, err := newConfig(npq, bindPort, enableMetrics, kubeconfig)
	if err != nil {
		return nil, err
	}
	s, err := cfg.New(Name, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}
	s.SecureServingInfo.CipherSuites = cipherSuites
	s.SecureServingInfo.MinTLSVersion = tlsMinVersion
	if err := installAPIGroup(s, aq, npq); err != nil {
		return nil, err
	}
	installHandlers(aq, npq, s)
	return &agentAPIServer{GenericAPIServer: s}, nil
}
