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
	"net"
	"net/http"
	"os"
	"path"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sversion "k8s.io/apimachinery/pkg/version"
	genericopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/healthz"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/addressgroup"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/appliedtogroup"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/featuregates"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/memberlist"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/multicast"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/networkpolicy"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovsflows"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovstracing"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/serviceexternalip"
	agentquerier "antrea.io/antrea/pkg/agent/querier"
	systeminstall "antrea.io/antrea/pkg/apis/system/install"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	"antrea.io/antrea/pkg/apiserver"
	"antrea.io/antrea/pkg/apiserver/handlers/loglevel"
	"antrea.io/antrea/pkg/apiserver/openapi"
	"antrea.io/antrea/pkg/apiserver/registry/system/supportbundle"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
	antreaversion "antrea.io/antrea/pkg/version"
)

const CertPairName = "antrea-agent-api"

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
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

func (s *agentAPIServer) GetCertData() []byte {
	secureServingInfo := s.GenericAPIServer.SecureServingInfo
	if secureServingInfo == nil {
		return nil
	}
	cert, _ := secureServingInfo.Cert.CurrentCertKeyContent()
	return cert
}

func installHandlers(aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, mq querier.AgentMulticastInfoQuerier, seipq querier.ServiceExternalIPStatusQuerier, s *genericapiserver.GenericAPIServer) {
	s.Handler.NonGoRestfulMux.HandleFunc("/loglevel", loglevel.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/podmulticaststats", multicast.HandleFunc(mq))
	s.Handler.NonGoRestfulMux.HandleFunc("/featuregates", featuregates.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/agentinfo", agentinfo.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/podinterfaces", podinterface.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/networkpolicies", networkpolicy.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/appliedtogroups", appliedtogroup.HandleFunc(npq))
	s.Handler.NonGoRestfulMux.HandleFunc("/addressgroups", addressgroup.HandleFunc(npq))
	s.Handler.NonGoRestfulMux.HandleFunc("/ovsflows", ovsflows.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/ovstracing", ovstracing.HandleFunc(aq))
	s.Handler.NonGoRestfulMux.HandleFunc("/serviceexternalip", serviceexternalip.HandleFunc(seipq))
	s.Handler.NonGoRestfulMux.HandleFunc("/memberlist", memberlist.HandleFunc(aq))
}

func installAPIGroup(s *genericapiserver.GenericAPIServer, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, v4Enabled, v6Enabled bool) error {
	systemGroup := genericapiserver.NewDefaultAPIGroupInfo(systemv1beta1.GroupName, scheme, metav1.ParameterCodec, codecs)
	systemStorage := map[string]rest.Storage{}
	supportBundleStorage := supportbundle.NewAgentStorage(ovsctl.NewClient(aq.GetNodeConfig().OVSBridge), aq, npq, v4Enabled, v6Enabled)
	systemStorage["supportbundles"] = supportBundleStorage.SupportBundle
	systemStorage["supportbundles/download"] = supportBundleStorage.Download
	systemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage
	return s.InstallAPIGroup(&systemGroup)
}

// New creates an APIServer for running in antrea agent.
func New(aq agentquerier.AgentQuerier,
	npq querier.AgentNetworkPolicyInfoQuerier,
	mq querier.AgentMulticastInfoQuerier,
	seipq querier.ServiceExternalIPStatusQuerier,
	secureServing *genericoptions.SecureServingOptionsWithLoopback,
	authentication *genericoptions.DelegatingAuthenticationOptions,
	authorization *genericoptions.DelegatingAuthorizationOptions,
	enableMetrics bool,
	kubeconfig string,
	loopbackClientTokenPath string,
	v4Enabled,
	v6Enabled bool,
) (*agentAPIServer, error) {
	cfg, err := newConfig(aq, npq, secureServing, authentication, authorization, enableMetrics, kubeconfig, loopbackClientTokenPath)
	if err != nil {
		return nil, err
	}
	s, err := cfg.New(CertPairName, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}
	if err := installAPIGroup(s, aq, npq, v4Enabled, v6Enabled); err != nil {
		return nil, err
	}
	installHandlers(aq, npq, mq, seipq, s)
	return &agentAPIServer{GenericAPIServer: s}, nil
}

func newConfig(aq agentquerier.AgentQuerier,
	npq querier.AgentNetworkPolicyInfoQuerier,
	secureServing *genericoptions.SecureServingOptionsWithLoopback,
	authentication *genericoptions.DelegatingAuthenticationOptions,
	authorization *genericoptions.DelegatingAuthorizationOptions,
	enableMetrics bool,
	kubeconfig string,
	loopbackClientTokenPath string,
) (*genericapiserver.CompletedConfig, error) {
	// kubeconfig file is useful when antrea-agent isn't running as a Pod.
	if len(kubeconfig) > 0 {
		authentication.RemoteKubeConfigFile = kubeconfig
		authorization.RemoteKubeConfigFile = kubeconfig
	}

	// Set the PairName but leave certificate directory blank to generate in-memory by default.
	secureServing.ServerCert.CertDirectory = ""
	secureServing.ServerCert.PairName = CertPairName

	if err := secureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}); err != nil {
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
	if err := os.MkdirAll(path.Dir(loopbackClientTokenPath), os.ModeDir); err != nil {
		return nil, fmt.Errorf("error when creating dirs of token file: %v", err)
	}
	if err := os.WriteFile(loopbackClientTokenPath, []byte(serverConfig.LoopbackClientConfig.BearerToken), 0600); err != nil {
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
	// Add readiness probe to check the status of watchers.
	watcherCheck := healthz.NamedCheck("watcher", func(_ *http.Request) error {
		if npq.GetControllerConnectionStatus() {
			return nil
		}
		return fmt.Errorf("some watchers may not be connected")
	})
	serverConfig.ReadyzChecks = append(serverConfig.ReadyzChecks, watcherCheck)
	// Add liveness probe to check the connection with OFSwitch.
	// This helps automatic recovery if some issues cause OFSwitch reconnection to not work properly, e.g. issue #4092.
	ovsConnCheck := healthz.NamedCheck("ovs", func(_ *http.Request) error {
		if aq.GetOpenflowClient().IsConnected() {
			return nil
		}
		return fmt.Errorf("disconnected from OFSwitch")
	})
	serverConfig.LivezChecks = append(serverConfig.LivezChecks, ovsConnCheck)
	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(
		openapi.GetOpenAPIDefinitions,
		genericopenapi.NewDefinitionNamer(apiserver.Scheme))

	completedServerCfg := serverConfig.Complete(nil)
	return &completedServerCfg, nil
}
