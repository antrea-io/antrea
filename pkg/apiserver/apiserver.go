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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"antrea.io/antrea/pkg/apis/controlplane"
	cpinstall "antrea.io/antrea/pkg/apis/controlplane/install"
	apistats "antrea.io/antrea/pkg/apis/stats"
	statsinstall "antrea.io/antrea/pkg/apis/stats/install"
	systeminstall "antrea.io/antrea/pkg/apis/system/install"
	system "antrea.io/antrea/pkg/apis/system/v1beta1"
	"antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/apiserver/handlers/endpoint"
	"antrea.io/antrea/pkg/apiserver/handlers/featuregates"
	"antrea.io/antrea/pkg/apiserver/handlers/loglevel"
	"antrea.io/antrea/pkg/apiserver/handlers/webhook"
	"antrea.io/antrea/pkg/apiserver/registry/controlplane/egressgroup"
	"antrea.io/antrea/pkg/apiserver/registry/controlplane/nodestatssummary"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/clustergroupmember"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/groupassociation"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"antrea.io/antrea/pkg/apiserver/registry/stats/antreaclusternetworkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/stats/antreanetworkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/stats/networkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/system/controllerinfo"
	"antrea.io/antrea/pkg/apiserver/registry/system/supportbundle"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/egress"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/controller/ipam"
	controllernetworkpolicy "antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/controller/querier"
	"antrea.io/antrea/pkg/controller/stats"
	"antrea.io/antrea/pkg/features"
	legacycontrolplane "antrea.io/antrea/pkg/legacyapis/controlplane"
	legacycpinstall "antrea.io/antrea/pkg/legacyapis/controlplane/install"
	legacyapistats "antrea.io/antrea/pkg/legacyapis/stats"
	legacystatsinstall "antrea.io/antrea/pkg/legacyapis/stats/install"
	legacysysteminstall "antrea.io/antrea/pkg/legacyapis/system/install"
	legacysystem "antrea.io/antrea/pkg/legacyapis/system/v1beta1"
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
	statsinstall.Install(Scheme)

	legacycpinstall.Install(Scheme)
	legacysysteminstall.Install(Scheme)
	legacystatsinstall.Install(Scheme)

	// We need to add the options to empty v1, see sample-apiserver/pkg/apiserver/apiserver.go.
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})
}

// ExtraConfig holds custom apiserver config.
type ExtraConfig struct {
	k8sClient                     kubernetes.Interface
	addressGroupStore             storage.Interface
	appliedToGroupStore           storage.Interface
	networkPolicyStore            storage.Interface
	egressGroupStore              storage.Interface
	controllerQuerier             querier.ControllerQuerier
	endpointQuerier               controllernetworkpolicy.EndpointQuerier
	networkPolicyController       *controllernetworkpolicy.NetworkPolicyController
	egressController              *egress.EgressController
	externalIPPoolController      *externalippool.ExternalIPPoolController
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
	k8sClient kubernetes.Interface,
	addressGroupStore, appliedToGroupStore, networkPolicyStore, groupStore, egressGroupStore storage.Interface,
	caCertController *certificate.CACertController,
	statsAggregator *stats.Aggregator,
	controllerQuerier querier.ControllerQuerier,
	networkPolicyStatusController *controllernetworkpolicy.StatusController,
	endpointQuerier controllernetworkpolicy.EndpointQuerier,
	npController *controllernetworkpolicy.NetworkPolicyController,
	egressController *egress.EgressController) *Config {
	return &Config{
		genericConfig: genericConfig,
		extraConfig: ExtraConfig{
			k8sClient:                     k8sClient,
			addressGroupStore:             addressGroupStore,
			appliedToGroupStore:           appliedToGroupStore,
			networkPolicyStore:            networkPolicyStore,
			egressGroupStore:              egressGroupStore,
			caCertController:              caCertController,
			statsAggregator:               statsAggregator,
			controllerQuerier:             controllerQuerier,
			endpointQuerier:               endpointQuerier,
			networkPolicyController:       npController,
			networkPolicyStatusController: networkPolicyStatusController,
			egressController:              egressController,
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
	egressGroupStorage := egressgroup.NewREST(c.extraConfig.egressGroupStore)
	cpGroup := genericapiserver.NewDefaultAPIGroupInfo(controlplane.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	cpv1beta2Storage := map[string]rest.Storage{}
	cpv1beta2Storage["addressgroups"] = addressGroupStorage
	cpv1beta2Storage["appliedtogroups"] = appliedToGroupStorage
	cpv1beta2Storage["networkpolicies"] = networkPolicyStorage
	cpv1beta2Storage["networkpolicies/status"] = networkPolicyStatusStorage
	cpv1beta2Storage["nodestatssummaries"] = nodeStatsSummaryStorage
	cpv1beta2Storage["groupassociations"] = groupAssociationStorage
	cpv1beta2Storage["clustergroupmembers"] = clusterGroupMembershipStorage
	cpv1beta2Storage["egressgroups"] = egressGroupStorage
	cpGroup.VersionedResourcesStorageMap["v1beta2"] = cpv1beta2Storage

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

	groups := []*genericapiserver.APIGroupInfo{&cpGroup, &systemGroup, &statsGroup}

	// legacy groups
	legacyCPGroup := genericapiserver.NewDefaultAPIGroupInfo(legacycontrolplane.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	legacyCPv1beta2Storage := map[string]rest.Storage{}
	legacyCPv1beta2Storage["addressgroups"] = addressGroupStorage
	legacyCPv1beta2Storage["appliedtogroups"] = appliedToGroupStorage
	legacyCPv1beta2Storage["networkpolicies"] = networkPolicyStorage
	legacyCPv1beta2Storage["networkpolicies/status"] = networkPolicyStatusStorage
	legacyCPv1beta2Storage["nodestatssummaries"] = nodeStatsSummaryStorage
	legacyCPv1beta2Storage["groupassociations"] = groupAssociationStorage
	legacyCPv1beta2Storage["clustergroupmembers"] = clusterGroupMembershipStorage
	legacyCPGroup.VersionedResourcesStorageMap["v1beta2"] = legacyCPv1beta2Storage

	legacySystemGroup := genericapiserver.NewDefaultAPIGroupInfo(legacysystem.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	legacySystemGroup.VersionedResourcesStorageMap["v1beta1"] = systemStorage

	legacyStatsGroup := genericapiserver.NewDefaultAPIGroupInfo(legacyapistats.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	legacyStatsGroup.VersionedResourcesStorageMap["v1alpha1"] = statsStorage

	// legacy API groups
	groups = append(groups, &legacyCPGroup, &legacySystemGroup, &legacyStatsGroup)

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
	// Also check: https://github.com/antrea-io/antrea/issues/494
	deprecatedAPIServices := []string{
		"v1beta1.networking.antrea.tanzu.vmware.com",
		"v1beta1.controlplane.antrea.tanzu.vmware.com",
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

func installHandlers(c *ExtraConfig, s *genericapiserver.GenericAPIServer) {
	s.Handler.NonGoRestfulMux.HandleFunc("/loglevel", loglevel.HandleFunc())
	s.Handler.NonGoRestfulMux.HandleFunc("/featuregates", featuregates.HandleFunc(c.k8sClient))
	s.Handler.NonGoRestfulMux.HandleFunc("/endpoint", endpoint.HandleFunc(c.endpointQuerier))
	// Webhook to mutate Namespace labels and add its metadata.name as a label
	s.Handler.NonGoRestfulMux.HandleFunc("/mutate/namespace", webhook.HandleMutationLabels())
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		// Get new NetworkPolicyMutator
		m := controllernetworkpolicy.NewNetworkPolicyMutator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related mutation
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/acnp", webhook.HandleMutationNetworkPolicy(m))
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/anp", webhook.HandleMutationNetworkPolicy(m))

		// Get new NetworkPolicyValidator
		v := controllernetworkpolicy.NewNetworkPolicyValidator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related validation
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/tier", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/acnp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/anp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/clustergroup", webhook.HandlerForValidateFunc(v.Validate))

		// Install handlers for CRD conversion between versions
		s.Handler.NonGoRestfulMux.HandleFunc("/convert/clustergroup", webhook.HandleCRDConversion(controllernetworkpolicy.ConvertClusterGroupCRD))

		// Install a post start hook to initialize Tiers on start-up
		s.AddPostStartHook("initialize-tiers", func(context genericapiserver.PostStartHookContext) error {
			go c.networkPolicyController.InitializeTiers()
			return nil
		})
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/egress", webhook.HandlerForValidateFunc(c.egressController.ValidateEgress))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/externalippool", webhook.HandlerForValidateFunc(c.externalIPPoolController.ValidateExternalIPPool))
	}

	if features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/ippool", webhook.HandlerForValidateFunc(ipam.ValidateIPPool))
	}
}

func DefaultCAConfig() *certificate.CAConfig {
	return &certificate.CAConfig{
		CAConfigMapName: certificate.AntreaCAConfigMapName,
		APIServiceNames: []string{
			"v1alpha1.stats.antrea.tanzu.vmware.com",
			"v1beta1.controlplane.antrea.tanzu.vmware.com",
			"v1beta2.controlplane.antrea.tanzu.vmware.com",
			"v1beta1.system.antrea.tanzu.vmware.com",
			"v1alpha1.stats.antrea.io",
			"v1beta1.system.antrea.io",
			"v1beta2.controlplane.antrea.io",
		},
		ValidatingWebhooks: []string{
			"crdvalidator.antrea.tanzu.vmware.com",
			"crdvalidator.antrea.io",
		},
		MutationWebhooks: []string{
			"crdmutator.antrea.tanzu.vmware.com",
			"crdmutator.antrea.io",
		},
		OptionalMutationWebhooks: []string{
			"labelsmutator.antrea.io",
		},
		CRDsWithConversionWebhooks: []string{
			"clustergroups.crd.antrea.io",
		},
		CertDir:           "/var/run/antrea/antrea-controller-tls",
		SelfSignedCertDir: "/var/run/antrea/antrea-controller-self-signed",
		CertReadyTimeout:  2 * time.Minute,
		MaxRotateDuration: time.Hour * (24 * 365),
		ServiceName:       certificate.AntreaServiceName,
		PairName:          "antrea-controller",
	}
}
