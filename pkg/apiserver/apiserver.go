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
	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	networkinginstall "github.com/vmware-tanzu/antrea/pkg/apis/networking/install"
	apistats "github.com/vmware-tanzu/antrea/pkg/apis/stats"
	statsinstall "github.com/vmware-tanzu/antrea/pkg/apis/stats/install"
	systeminstall "github.com/vmware-tanzu/antrea/pkg/apis/system/install"
	system "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/certificate"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/handlers/endpoint"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/handlers/loglevel"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/handlers/webhook"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/controlplane/nodestatssummary"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/clustergroupmember"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/groupassociation"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/stats/antreaclusternetworkpolicystats"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/stats/antreanetworkpolicystats"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/stats/networkpolicystats"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/supportbundle"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	controllernetworkpolicy "github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
	"github.com/vmware-tanzu/antrea/pkg/controller/stats"
	"github.com/vmware-tanzu/antrea/pkg/features"
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
	networkinginstall.Install(Scheme)
	statsinstall.Install(Scheme)
	// We need to add the options to empty v1, see sample-apiserver/pkg/apiserver/apiserver.go.
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})
}

// ExtraConfig holds custom apiserver config.
type ExtraConfig struct {
	addressGroupStore             storage.Interface
	appliedToGroupStore           storage.Interface
	networkPolicyStore            storage.Interface
	controllerQuerier             querier.ControllerQuerier
	endpointQuerier               controllernetworkpolicy.EndpointQuerier
	networkPolicyController       *controllernetworkpolicy.NetworkPolicyController
	caCertController              *certificate.CACertController
	statsAggregator               *stats.Aggregator
	networkPolicyStatusController *controllernetworkpolicy.StatusController
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
	addressGroupStore, appliedToGroupStore, networkPolicyStore, groupStore storage.Interface,
	caCertController *certificate.CACertController,
	statsAggregator *stats.Aggregator,
	controllerQuerier querier.ControllerQuerier,
	networkPolicyStatusController *controllernetworkpolicy.StatusController,
	endpointQuerier controllernetworkpolicy.EndpointQuerier,
	npController *controllernetworkpolicy.NetworkPolicyController) *Config {
	return &Config{
		genericConfig: genericConfig,
		extraConfig: ExtraConfig{
			addressGroupStore:             addressGroupStore,
			appliedToGroupStore:           appliedToGroupStore,
			networkPolicyStore:            networkPolicyStore,
			caCertController:              caCertController,
			statsAggregator:               statsAggregator,
			controllerQuerier:             controllerQuerier,
			endpointQuerier:               endpointQuerier,
			networkPolicyController:       npController,
			networkPolicyStatusController: networkPolicyStatusController,
		},
	}
}

func (c *Config) Complete(informers informers.SharedInformerFactory) completedConfig {
	return completedConfig{c.genericConfig.Complete(informers), &c.extraConfig}
}

func installAPIGroup(s *APIServer, c completedConfig) error {
	addressGroupStorage := addressgroup.NewREST(c.extraConfig.addressGroupStore)
	appliedToGroupStorage := appliedtogroup.NewREST(c.extraConfig.appliedToGroupStore)
	networkPolicyStorage := networkpolicy.NewREST(c.extraConfig.networkPolicyStore)
	networkPolicyStatusStorage := networkpolicy.NewStatusREST(c.extraConfig.networkPolicyStatusController)
	clusterGroupMembershipStorage := clustergroupmember.NewREST(c.extraConfig.networkPolicyController)
	groupAssociationStorage := groupassociation.NewREST(c.extraConfig.networkPolicyController)
	nodeStatsSummaryStorage := nodestatssummary.NewREST(c.extraConfig.statsAggregator)
	cpGroup := genericapiserver.NewDefaultAPIGroupInfo(controlplane.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	cpv1beta1Storage := map[string]rest.Storage{}
	cpv1beta1Storage["addressgroups"] = addressGroupStorage
	cpv1beta1Storage["appliedtogroups"] = appliedToGroupStorage
	cpv1beta1Storage["networkpolicies"] = networkPolicyStorage
	cpv1beta1Storage["nodestatssummaries"] = nodeStatsSummaryStorage
	cpGroup.VersionedResourcesStorageMap["v1beta1"] = cpv1beta1Storage
	cpv1beta2Storage := map[string]rest.Storage{}
	cpv1beta2Storage["addressgroups"] = addressGroupStorage
	cpv1beta2Storage["appliedtogroups"] = appliedToGroupStorage
	cpv1beta2Storage["networkpolicies"] = networkPolicyStorage
	cpv1beta2Storage["networkpolicies/status"] = networkPolicyStatusStorage
	cpv1beta2Storage["nodestatssummaries"] = nodeStatsSummaryStorage
	cpv1beta2Storage["groupassociations"] = groupAssociationStorage
	cpv1beta2Storage["clustergroupmembers"] = clusterGroupMembershipStorage
	cpGroup.VersionedResourcesStorageMap["v1beta2"] = cpv1beta2Storage

	// TODO: networkingGroup is the legacy group of controlplane NetworkPolicy APIs. To allow live upgrades from up to
	// two minor versions, the APIs must be kept for two minor releases before it can be deleted.
	networkingGroup := genericapiserver.NewDefaultAPIGroupInfo(networking.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	networkingStorage := map[string]rest.Storage{}
	networkingStorage["addressgroups"] = addressGroupStorage
	networkingStorage["appliedtogroups"] = appliedToGroupStorage
	networkingStorage["networkpolicies"] = networkPolicyStorage
	networkingGroup.VersionedResourcesStorageMap["v1beta1"] = networkingStorage

	systemGroup := genericapiserver.NewDefaultAPIGroupInfo(system.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	systemStorage := map[string]rest.Storage{}
	systemStorage["controllerinfos"] = controllerinfo.NewREST(c.extraConfig.controllerQuerier)
	bundleStorage := supportbundle.NewControllerStorage()
	systemStorage["supportbundles"] = bundleStorage.SupportBundle
	systemStorage["supportbundles/download"] = bundleStorage.Download
	systemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage

	statsGroup := genericapiserver.NewDefaultAPIGroupInfo(apistats.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	statsStorage := map[string]rest.Storage{}
	statsStorage["networkpolicystats"] = networkpolicystats.NewREST(c.extraConfig.statsAggregator)
	statsStorage["antreaclusternetworkpolicystats"] = antreaclusternetworkpolicystats.NewREST(c.extraConfig.statsAggregator)
	statsStorage["antreanetworkpolicystats"] = antreanetworkpolicystats.NewREST(c.extraConfig.statsAggregator)
	statsGroup.VersionedResourcesStorageMap["v1alpha1"] = statsStorage

	groups := []*genericapiserver.APIGroupInfo{&cpGroup, &networkingGroup, &systemGroup, &statsGroup}
	for _, apiGroupInfo := range groups {
		if err := s.GenericAPIServer.InstallAPIGroup(apiGroupInfo); err != nil {
			return err
		}
	}
	return nil
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
	installHandlers(c.extraConfig, s.GenericAPIServer)

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
	deprecatedAPIServices := []string{}
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

func installHandlers(c *ExtraConfig, s *genericapiserver.GenericAPIServer) {
	s.Handler.NonGoRestfulMux.HandleFunc("/loglevel", loglevel.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/endpoint", endpoint.HandleFunc(c.endpointQuerier))
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		// Webhook to mutate Namespace/Service labels and add its metadata.name as a label
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/addlabels", webhook.HandleMutationLabels())

		// Get new NetworkPolicyMutator
		m := controllernetworkpolicy.NewNetworkPolicyMutator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related mutation
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/acnp", webhook.HandleMutationNetworkPolicy(m))
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/anp", webhook.HandleMutationNetworkPolicy(m))

		// Get new NetworkPolicyValidator
		v := controllernetworkpolicy.NewNetworkPolicyValidator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related validation
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/tier", webhook.HandleValidationNetworkPolicy(v))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/acnp", webhook.HandleValidationNetworkPolicy(v))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/anp", webhook.HandleValidationNetworkPolicy(v))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/clustergroup", webhook.HandleValidationNetworkPolicy(v))
		// Install a post start hook to initialize Tiers on start-up
		s.AddPostStartHook("initialize-tiers", func(context genericapiserver.PostStartHookContext) error {
			go c.networkPolicyController.InitializeTiers()
			return nil
		})
	}
}
