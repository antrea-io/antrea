// Copyright 2020 Antrea Authors
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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sversion "k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/ovsflows"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/ovstracing"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/podinterface"
	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	systeminstall "github.com/vmware-tanzu/antrea/pkg/apis/system/install"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/handlers/loglevel"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/supportbundle"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/pkg/querier"
	antreaversion "github.com/vmware-tanzu/antrea/pkg/version"
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
	cfg, err := newConfig(bindPort, enableMetrics, kubeconfig)
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

func newConfig(bindPort int, enableMetrics bool, kubeconfig string) (*genericapiserver.CompletedConfig, error) {
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths("/healthz")

	// kubeconfig file is useful when antrea-agent isn't not running as a pod
	if len(kubeconfig) > 0 {
		authentication.RemoteKubeConfigFile = kubeconfig
		authorization.RemoteKubeConfigFile = kubeconfig
	}

	// Set the PairName but leave certificate directory blank to generate in-memory by default.
	secureServing.ServerCert.CertDirectory = ""
	secureServing.ServerCert.PairName = Name
	secureServing.BindAddress = net.ParseIP("0.0.0.0")
	secureServing.BindPort = bindPort

	if err := secureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}
	serverConfig := genericapiserver.NewConfig(codecs)
	if err := secureServing.ApplyTo(&serverConfig.SecureServing, &serverConfig.LoopbackClientConfig); err != nil {
		return nil, err
	}
	if err := authentication.ApplyTo(&serverConfig.Authentication, serverConfig.SecureServing, nil); err != nil {
		return nil, err
	}
	if err := authorization.ApplyTo(&serverConfig.Authorization); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path.Dir(TokenPath), os.ModeDir); err != nil {
		return nil, fmt.Errorf("error when creating dirs of token file: %v", err)
	}
	if err := ioutil.WriteFile(TokenPath, []byte(serverConfig.LoopbackClientConfig.BearerToken), 0600); err != nil {
		return nil, fmt.Errorf("error when writing loopback access token to file: %v", err)
	}
	v := antreaversion.GetVersion()
	serverConfig.Version = &k8sversion.Info{
		Major:        fmt.Sprint(v.Major),
		Minor:        fmt.Sprint(v.Minor),
		GitVersion:   v.String(),
		GitTreeState: antreaversion.GitTreeState,
		GitCommit:    antreaversion.GetGitSHA(),
	}
	serverConfig.EnableMetrics = enableMetrics

	completedServerCfg := serverConfig.Complete(nil)
	return &completedServerCfg, nil
}
