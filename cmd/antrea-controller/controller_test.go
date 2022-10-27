// Copyright 2023 Antrea Authors
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

package main

import (
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	fakeapiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apiserver/pkg/server"
	clientset "k8s.io/client-go/kubernetes"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	componentbaseconfig "k8s.io/component-base/config"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	fakeaggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	mockgenericoptions "antrea.io/antrea/cmd/antrea-controller/testing"
	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/apiserver"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	crdfake "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/signals"
)

func TestRunController(t *testing.T) {
	createK8sClient = func(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (
		clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, apiextensionclientset.Interface, mcclientset.Interface, error) {
		aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
		apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
		return fakeclientset.NewSimpleClientset(), aggregatorClientset, crdfake.NewSimpleClientset(), apiExtensionClient, mcfake.NewSimpleClientset(), nil
	}

	var err error
	apiserver.CertDir, err = os.MkdirTemp("", "antrea-controller-tls")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(apiserver.CertDir)
	}()

	apiserver.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-controller-self-signed")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(apiserver.SelfSignedCertDir)
	}()

	tokenPath, err := os.CreateTemp("", "loopback-client-token")
	require.NoError(t, err)
	apiserver.TokenPath = tokenPath.Name()
	defer func() {
		_ = os.RemoveAll(tokenPath.Name())
	}()

	opts := newOptions()
	opts.configFile = "./testing/testdata/controller_conf.yml"
	if err := opts.complete(); err != nil {
		t.Errorf("Complete antrea controller config error: %v", err)
	}

	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "17.0.0.1")
	_ = os.Setenv("KUBERNETES_SERVICE_PORT", "1234")

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	mockAuthentication := mockgenericoptions.NewMockAuthentication(ctl)
	mockAuthentication.EXPECT().ApplyTo(&server.AuthenticationInfo{}, gomock.Any(), nil).Return(nil)
	mockAuthorization := mockgenericoptions.NewMockAuthorization(ctl)
	mockAuthorization.EXPECT().ApplyTo(&server.AuthorizationInfo{}).Return(nil)

	authentication = NewDelegatingAuthenticationOptionsWarp(mockAuthentication)
	authorization = NewDelegatingAuthorizationOptionsWarp(mockAuthorization)

	go func() {
		time.Sleep(1 * time.Second)
		signals.GenerateStopSignal()
	}()
	if err := run(opts); err != nil {
		t.Errorf("Run antrea controller error: %v", err)
	}
}
