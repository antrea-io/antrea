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
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	systeminstall "antrea.io/antrea/pkg/apis/system/install"
	"antrea.io/antrea/pkg/apiserver/handlers/loglevel"
	"antrea.io/antrea/pkg/flowaggregator/apiserver/handlers/flowrecords"
	"antrea.io/antrea/pkg/flowaggregator/apiserver/handlers/recordmetrics"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	antreaversion "antrea.io/antrea/pkg/version"
)

const (
	Name = "flow-aggregator-api"
	// authenticationTimeout specifies a time limit for requests made by the authorization webhook client
	// The default value (10 seconds) is not long enough as defined in
	// https://pkg.go.dev/k8s.io/apiserver@v0.21.0/pkg/server/options#NewDelegatingAuthenticationOptions
	// A value of zero means no timeout.
	authenticationTimeout = 0
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	codecs = serializer.NewCodecFactory(scheme)
	// #nosec G101: false positive triggered by variable name which includes "token"
	TokenPath = "/var/run/antrea/apiserver/loopback-client-token"
)

func init() {
	systeminstall.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
}

type flowAggregatorAPIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

func (s *flowAggregatorAPIServer) Run(stopCh <-chan struct{}) error {
	return s.GenericAPIServer.PrepareRun().Run(stopCh)
}

func installHandlers(s *genericapiserver.GenericAPIServer, faq querier.FlowAggregatorQuerier) {
	s.Handler.NonGoRestfulMux.HandleFunc("/flowrecords", flowrecords.HandleFunc(faq))
	s.Handler.NonGoRestfulMux.HandleFunc("/recordmetrics", recordmetrics.HandleFunc(faq))
	s.Handler.NonGoRestfulMux.HandleFunc("/loglevel", loglevel.HandleFunc())
}

// New creates an APIServer for running in flow aggregator.
func New(faq querier.FlowAggregatorQuerier, bindPort int, cipherSuites []uint16, tlsMinVersion uint16) (*flowAggregatorAPIServer, error) {
	cfg, err := newConfig(bindPort)
	if err != nil {
		return nil, err
	}
	s, err := cfg.New(Name, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}
	s.SecureServingInfo.CipherSuites = cipherSuites
	s.SecureServingInfo.MinTLSVersion = tlsMinVersion
	installHandlers(s, faq)
	return &flowAggregatorAPIServer{GenericAPIServer: s}, nil
}

func newConfig(bindPort int) (*genericapiserver.CompletedConfig, error) {
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths("/healthz", "/livez", "/readyz")

	// Set the PairName but leave certificate directory blank to generate in-memory by default.
	secureServing.ServerCert.CertDirectory = ""
	secureServing.ServerCert.PairName = Name
	secureServing.BindAddress = net.IPv4zero
	secureServing.BindPort = bindPort

	authentication.WithClientTimeout(authenticationTimeout)

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

	completedServerCfg := serverConfig.Complete(nil)
	return &completedServerCfg, nil
}
