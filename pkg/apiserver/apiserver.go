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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/informers"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	networkinginstall "github.com/vmware-tanzu/antrea/pkg/apis/networking/install"
	systeminstall "github.com/vmware-tanzu/antrea/pkg/apis/system/install"
	system "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
)

func init() {
	networkinginstall.Install(Scheme)
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
}

// Config defines the config for Antrea apiserver.
type Config struct {
	genericConfig *genericapiserver.Config
	extraConfig   ExtraConfig
}

// APIServer contains state for a Kubernetes cluster apiserver.
type APIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	genericConfig genericapiserver.CompletedConfig
	extraConfig   *ExtraConfig
}

func NewConfig(
	genericConfig *genericapiserver.Config,
	addressGroupStore, appliedToGroupStore, networkPolicyStore storage.Interface,
	controllerQuerier querier.ControllerQuerier) *Config {
	return &Config{
		genericConfig: genericConfig,
		extraConfig: ExtraConfig{
			addressGroupStore:   addressGroupStore,
			appliedToGroupStore: appliedToGroupStore,
			networkPolicyStore:  networkPolicyStore,
			controllerQuerier:   controllerQuerier,
		},
	}
}

func (c *Config) Complete(informers informers.SharedInformerFactory) completedConfig {
	return completedConfig{c.genericConfig.Complete(informers), &c.extraConfig}
}

func (c completedConfig) New() (*APIServer, error) {
	genericServer, err := c.genericConfig.New("antrea-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &APIServer{
		GenericAPIServer: genericServer,
	}

	networkingGroup := genericapiserver.NewDefaultAPIGroupInfo(networking.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	networkingStorage := map[string]rest.Storage{}
	networkingStorage["addressgroups"] = addressgroup.NewREST(c.extraConfig.addressGroupStore)
	networkingStorage["appliedtogroups"] = appliedtogroup.NewREST(c.extraConfig.appliedToGroupStore)
	networkingStorage["networkpolicies"] = networkpolicy.NewREST(c.extraConfig.networkPolicyStore)
	networkingGroup.VersionedResourcesStorageMap["v1beta1"] = networkingStorage

	systemGroup := genericapiserver.NewDefaultAPIGroupInfo(system.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	systemStorage := map[string]rest.Storage{}
	systemStorage["controllerinfos"] = controllerinfo.NewREST(c.extraConfig.controllerQuerier)
	systemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage

	groups := []*genericapiserver.APIGroupInfo{&networkingGroup, &systemGroup}
	for _, apiGroupInfo := range groups {
		if err := s.GenericAPIServer.InstallAPIGroup(apiGroupInfo); err != nil {
			return nil, err
		}
	}

	return s, nil
}
