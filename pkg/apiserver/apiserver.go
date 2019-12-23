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
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/install"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
)

func init() {
	install.Install(Scheme)
	// We need to add the options to empty v1, see sample-apiserver/pkg/apiserver/apiserver.go.
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})
}

// ExtraConfig holds custom apiserver config.
type ExtraConfig struct {
	AddressGroupStore   storage.Interface
	AppliedToGroupStore storage.Interface
	NetworkPolicyStore  storage.Interface
}

// Config defines the config for Antrea apiserver.
type Config struct {
	GenericConfig *genericapiserver.Config
	ExtraConfig   ExtraConfig
}

// APIServer contains state for a Kubernetes cluster apiserver.
type APIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

func (c *Config) Complete(informers informers.SharedInformerFactory) completedConfig {
	return completedConfig{c.GenericConfig.Complete(informers), &c.ExtraConfig}
}

func (c completedConfig) New() (*APIServer, error) {
	genericServer, err := c.GenericConfig.New("antrea-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &APIServer{
		GenericAPIServer: genericServer,
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(networking.GroupName, Scheme, metav1.ParameterCodec, Codecs)

	v1beta1Storage := map[string]rest.Storage{}
	v1beta1Storage["addressgroups"] = addressgroup.NewREST(c.ExtraConfig.AddressGroupStore)
	v1beta1Storage["appliedtogroups"] = appliedtogroup.NewREST(c.ExtraConfig.AppliedToGroupStore)
	v1beta1Storage["networkpolicies"] = networkpolicy.NewREST(c.ExtraConfig.NetworkPolicyStore)
	apiGroupInfo.VersionedResourcesStorageMap["v1beta1"] = v1beta1Storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
}
