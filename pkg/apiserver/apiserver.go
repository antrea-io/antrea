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

package apiserver

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/informers"
	"k8s.io/klog"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	cpinstall "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/install"
	systeminstall "github.com/vmware-tanzu/antrea/pkg/apis/system/install"
	system "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/certificate"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/handlers/endpoint"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/supportbundle"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	networkquery "github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
	// #nosec G101: false positive triggered by variable name which includes "token"
	TokenPath = "/var/run/antrea/apiserver/loopback-client-token"
)

func init() {
	cpinstall.Install(Scheme)
	systeminstall.Install(Scheme)
	// We need to add the options to empty v1, see sample-apiserver/pkg/apiserver/apiserver.go.
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})
}

// ExtraConfig holds custom apiserver config.
type ExtraConfig struct {
	addressGroupStore   storage.Interface
	appliedToGroupStore storage.Interface
	networkPolicyStore  storage.Interface
	controllerQuerier   querier.ControllerQuerier
	endpointQuerier     networkquery.EndpointQuerier
	caCertController    *certificate.CACertController
}

// Config defines the config for Antrea apiserver.
type Config struct {
	genericConfig *genericapiserver.Config
	extraConfig   ExtraConfig
}

// APIServer contains state for a Kubernetes cluster apiserver.
type APIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
	caCertController *certificate.CACertController
}

func (s *APIServer) Run(stopCh <-chan struct{}) error {
	// Make sure CACertController runs once to publish the CA cert before starting APIServer.
	if err := s.caCertController.RunOnce(); err != nil {
		klog.Warningf("caCertController RunOnce failed: %v", err)
	}
	go s.caCertController.Run(1, stopCh)

	return s.GenericAPIServer.PrepareRun().Run(stopCh)
}

type completedConfig struct {
	genericConfig genericapiserver.CompletedConfig
	extraConfig   *ExtraConfig
}

func NewConfig(
	genericConfig *genericapiserver.Config,
	addressGroupStore, appliedToGroupStore, networkPolicyStore storage.Interface,
	caCertController *certificate.CACertController,
	controllerQuerier querier.ControllerQuerier,
	endpointQuerier networkquery.EndpointQuerier) *Config {
	return &Config{
		genericConfig: genericConfig,
		extraConfig: ExtraConfig{
			addressGroupStore:   addressGroupStore,
			appliedToGroupStore: appliedToGroupStore,
			networkPolicyStore:  networkPolicyStore,
			caCertController:    caCertController,
			controllerQuerier:   controllerQuerier,
			endpointQuerier:     endpointQuerier,
		},
	}
}

func (c *Config) Complete(informers informers.SharedInformerFactory) completedConfig {
	return completedConfig{c.genericConfig.Complete(informers), &c.extraConfig}
}

func installAPIGroup(s *APIServer, c completedConfig) error {
	cpGroup := genericapiserver.NewDefaultAPIGroupInfo(controlplane.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	cpStorage := map[string]rest.Storage{}
	cpStorage["addressgroups"] = addressgroup.NewREST(c.extraConfig.addressGroupStore)
	cpStorage["appliedtogroups"] = appliedtogroup.NewREST(c.extraConfig.appliedToGroupStore)
	cpStorage["networkpolicies"] = networkpolicy.NewREST(c.extraConfig.networkPolicyStore)
	cpGroup.VersionedResourcesStorageMap["v1beta1"] = cpStorage

	systemGroup := genericapiserver.NewDefaultAPIGroupInfo(system.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	systemStorage := map[string]rest.Storage{}
	systemStorage["controllerinfos"] = controllerinfo.NewREST(c.extraConfig.controllerQuerier)
	bundleStorage := supportbundle.NewControllerStorage()
	systemStorage["supportbundles"] = bundleStorage.SupportBundle
	systemStorage["supportbundles/download"] = bundleStorage.Download
	systemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage

	groups := []*genericapiserver.APIGroupInfo{&cpGroup, &systemGroup}
	for _, apiGroupInfo := range groups {
		if err := s.GenericAPIServer.InstallAPIGroup(apiGroupInfo); err != nil {
			return err
		}
	}
	return nil
}

func installHandlers(eq networkquery.EndpointQuerier, s *genericapiserver.GenericAPIServer) {
	s.Handler.NonGoRestfulMux.HandleFunc("/endpoint", endpoint.HandleFunc(eq))
}

func (c completedConfig) New() (*APIServer, error) {
	genericServer, err := c.genericConfig.New("antrea-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &APIServer{
		GenericAPIServer: genericServer,
		caCertController: c.extraConfig.caCertController,
	}

	if err := installAPIGroup(s, c); err != nil {
		return nil, err
	}

	installHandlers(c.extraConfig.endpointQuerier, s.GenericAPIServer)

	return s, nil
}

// CleanupDeprecatedAPIServices deletes the registered APIService resources for
// the deprecated Antrea API groups.
func CleanupDeprecatedAPIServices(aggregatorClient clientset.Interface) error {
	// The APIService of a deprecated API group should be added to the slice.
	// After Antrea upgrades from an old version to a new version that
	// deprecates a registered APIService, the APIService should be deleted,
	// otherwise K8s will fail to delete an existing Namespace.
	// Also check: https://github.com/vmware-tanzu/antrea/issues/494
	deprecatedAPIServices := []string{
		"v1beta1.networking.antrea.tanzu.vmware.com",
	}
	for _, as := range deprecatedAPIServices {
		err := aggregatorClient.ApiregistrationV1().APIServices().Delete(context.TODO(), as, metav1.DeleteOptions{})
		if err == nil {
			klog.Infof("Deleted the deprecated APIService %s", as)
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
