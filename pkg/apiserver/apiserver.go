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
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"antrea.io/antrea/pkg/apis"
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
	"antrea.io/antrea/pkg/apiserver/registry/controlplane/supportbundlecollection"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/addressgroup"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/appliedtogroup"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/clustergroupmember"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/groupassociation"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/groupmember"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/ipgroupassociation"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/networkpolicy"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/networkpolicyevaluation"
	"antrea.io/antrea/pkg/apiserver/registry/stats/antreaclusternetworkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/stats/antreanetworkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/stats/multicastgroup"
	"antrea.io/antrea/pkg/apiserver/registry/stats/networkpolicystats"
	"antrea.io/antrea/pkg/apiserver/registry/system/controllerinfo"
	"antrea.io/antrea/pkg/apiserver/registry/system/supportbundle"
	"antrea.io/antrea/pkg/apiserver/storage"
	crdv1a2informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/egress"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/controller/ipam"
	controllernetworkpolicy "antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/controller/querier"
	"antrea.io/antrea/pkg/controller/stats"
	controllerbundlecollection "antrea.io/antrea/pkg/controller/supportbundlecollection"
	"antrea.io/antrea/pkg/controller/traceflow"
	"antrea.io/antrea/pkg/features"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
	// ParameterCodec defines methods for serializing and deserializing url values
	// to versioned API objects and back.
	parameterCodec = runtime.NewParameterCodec(Scheme)

	// antreaServedLabelSelector selects resources served by antrea-controller.
	antreaServedLabelSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app":       "antrea",
			"served-by": "antrea-controller",
		},
	}
)

func init() {
	cpinstall.Install(Scheme)
	systeminstall.Install(Scheme)
	statsinstall.Install(Scheme)

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
	bundleCollectionStore         storage.Interface
	podInformer                   coreinformers.PodInformer
	eeInformer                    crdv1a2informers.ExternalEntityInformer
	controllerQuerier             querier.ControllerQuerier
	endpointQuerier               controllernetworkpolicy.EndpointQuerier
	networkPolicyController       *controllernetworkpolicy.NetworkPolicyController
	egressController              *egress.EgressController
	externalIPPoolController      *externalippool.ExternalIPPoolController
	caCertController              *certificate.CACertController
	statsAggregator               *stats.Aggregator
	networkPolicyStatusController *controllernetworkpolicy.StatusController
	bundleCollectionController    *controllerbundlecollection.Controller
	traceflowController           *traceflow.Controller
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

func (s *APIServer) Run(ctx context.Context) error {
	// Make sure CACertController runs once to publish the CA cert before starting APIServer.
	if err := s.caCertController.RunOnce(ctx); err != nil {
		klog.Warningf("caCertController RunOnce failed: %v", err)
	}
	go s.caCertController.Run(ctx, 1)

	return s.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

type completedConfig struct {
	genericConfig genericapiserver.CompletedConfig
	extraConfig   *ExtraConfig
}

func NewConfig(
	genericConfig *genericapiserver.Config,
	k8sClient kubernetes.Interface,
	addressGroupStore, appliedToGroupStore, networkPolicyStore, egressGroupStore, supportBundleCollectionStore storage.Interface,
	podInformer coreinformers.PodInformer,
	eeInformer crdv1a2informers.ExternalEntityInformer,
	caCertController *certificate.CACertController,
	statsAggregator *stats.Aggregator,
	controllerQuerier querier.ControllerQuerier,
	networkPolicyStatusController *controllernetworkpolicy.StatusController,
	endpointQuerier controllernetworkpolicy.EndpointQuerier,
	npController *controllernetworkpolicy.NetworkPolicyController,
	egressController *egress.EgressController,
	externalIPPoolController *externalippool.ExternalIPPoolController,
	bundleCollectionController *controllerbundlecollection.Controller,
	traceflowController *traceflow.Controller) *Config {
	return &Config{
		genericConfig: genericConfig,
		extraConfig: ExtraConfig{
			k8sClient:                     k8sClient,
			addressGroupStore:             addressGroupStore,
			appliedToGroupStore:           appliedToGroupStore,
			networkPolicyStore:            networkPolicyStore,
			egressGroupStore:              egressGroupStore,
			bundleCollectionStore:         supportBundleCollectionStore,
			podInformer:                   podInformer,
			eeInformer:                    eeInformer,
			caCertController:              caCertController,
			statsAggregator:               statsAggregator,
			controllerQuerier:             controllerQuerier,
			endpointQuerier:               endpointQuerier,
			networkPolicyController:       npController,
			networkPolicyStatusController: networkPolicyStatusController,
			egressController:              egressController,
			externalIPPoolController:      externalIPPoolController,
			bundleCollectionController:    bundleCollectionController,
			traceflowController:           traceflowController,
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
	networkPolicyEvaluationStorage := networkpolicyevaluation.NewREST(controllernetworkpolicy.NewPolicyRuleQuerier(c.extraConfig.endpointQuerier))
	clusterGroupMembershipStorage := clustergroupmember.NewREST(c.extraConfig.networkPolicyController)
	groupMembershipStorage := groupmember.NewREST(c.extraConfig.networkPolicyController)
	groupAssociationStorage := groupassociation.NewREST(c.extraConfig.networkPolicyController)
	ipGroupAssociationStorage := ipgroupassociation.NewREST(c.extraConfig.podInformer, c.extraConfig.eeInformer, c.extraConfig.networkPolicyController, c.extraConfig.networkPolicyController)
	nodeStatsSummaryStorage := nodestatssummary.NewREST(c.extraConfig.statsAggregator)
	egressGroupStorage := egressgroup.NewREST(c.extraConfig.egressGroupStore)
	bundleCollectionStorage := supportbundlecollection.NewREST(c.extraConfig.bundleCollectionStore)
	bundleCollectionStatusStorage := supportbundlecollection.NewStatusREST(c.extraConfig.bundleCollectionController)
	cpGroup := genericapiserver.NewDefaultAPIGroupInfo(controlplane.GroupName, Scheme, parameterCodec, Codecs)
	cpv1beta2Storage := map[string]rest.Storage{}
	cpv1beta2Storage["addressgroups"] = addressGroupStorage
	cpv1beta2Storage["appliedtogroups"] = appliedToGroupStorage
	cpv1beta2Storage["networkpolicies"] = networkPolicyStorage
	cpv1beta2Storage["networkpolicies/status"] = networkPolicyStatusStorage
	cpv1beta2Storage["networkpolicyevaluation"] = networkPolicyEvaluationStorage
	cpv1beta2Storage["nodestatssummaries"] = nodeStatsSummaryStorage
	cpv1beta2Storage["groupassociations"] = groupAssociationStorage
	cpv1beta2Storage["ipgroupassociations"] = ipGroupAssociationStorage
	cpv1beta2Storage["clustergroupmembers"] = clusterGroupMembershipStorage
	cpv1beta2Storage["groupmembers"] = groupMembershipStorage
	cpv1beta2Storage["egressgroups"] = egressGroupStorage
	cpv1beta2Storage["supportbundlecollections"] = bundleCollectionStorage
	cpv1beta2Storage["supportbundlecollections/status"] = bundleCollectionStatusStorage
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
	statsStorage["multicastgroups"] = multicastgroup.NewREST(c.extraConfig.statsAggregator)
	statsGroup.VersionedResourcesStorageMap["v1alpha1"] = statsStorage

	groups := []*genericapiserver.APIGroupInfo{&cpGroup, &systemGroup, &statsGroup}

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
	s.Handler.NonGoRestfulMux.HandleFunc("/featuregates", featuregates.HandleFunc(c.k8sClient))
	s.Handler.NonGoRestfulMux.HandleFunc("/endpoint", endpoint.HandleFunc(c.endpointQuerier))
	// Webhook to mutate Namespace labels and add its metadata.name as a label
	s.Handler.NonGoRestfulMux.HandleFunc("/mutate/namespace", webhook.HandleMutationLabels())
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		// Get new NetworkPolicyMutator
		m := controllernetworkpolicy.NewNetworkPolicyMutator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related mutation
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/acnp", webhook.HandleMutationNetworkPolicy(m))
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/annp", webhook.HandleMutationNetworkPolicy(m))
		s.Handler.NonGoRestfulMux.HandleFunc("/mutate/anp", webhook.HandleMutationNetworkPolicy(m))

		// Get new NetworkPolicyValidator
		v := controllernetworkpolicy.NewNetworkPolicyValidator(c.networkPolicyController)
		// Install handlers for NetworkPolicy related validation
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/tier", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/acnp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/annp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/anp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/banp", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/clustergroup", webhook.HandlerForValidateFunc(v.Validate))
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/group", webhook.HandlerForValidateFunc(v.Validate))

		// Install a post start hook to initialize Tiers on start-up
		s.AddPostStartHook("initialize-tiers", func(context genericapiserver.PostStartHookContext) error {
			go c.networkPolicyController.InitializeTiers()
			return nil
		})
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/externalippool", webhook.HandlerForValidateFunc(c.externalIPPoolController.ValidateExternalIPPool))
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/egress", webhook.HandlerForValidateFunc(c.egressController.ValidateEgress))
	}

	if features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/ippool", webhook.HandlerForValidateFunc(ipam.ValidateIPPool))
	}

	if features.DefaultFeatureGate.Enabled(features.SupportBundleCollection) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/supportbundlecollection", webhook.HandlerForValidateFunc(c.bundleCollectionController.Validate))
	}

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		s.Handler.NonGoRestfulMux.HandleFunc("/validate/traceflow", webhook.HandlerForValidateFunc(c.traceflowController.Validate))
	}
}

func DefaultCAConfig() *certificate.CAConfig {
	return &certificate.CAConfig{
		CAConfigMapName:              apis.AntreaCAConfigMapName,
		TLSSecretName:                apis.AntreaControllerTLSSecretName,
		APIServiceSelector:           antreaServedLabelSelector,
		ValidatingWebhookSelector:    antreaServedLabelSelector,
		MutationWebhookSelector:      antreaServedLabelSelector,
		CRDConversionWebhookSelector: antreaServedLabelSelector,
		CertDir:                      "/var/run/antrea/antrea-controller-tls",
		SelfSignedCertDir:            "/var/run/antrea/antrea-controller-self-signed",
		CertReadyTimeout:             2 * time.Minute,
		MinValidDuration:             time.Hour * 24 * 90, // Rotate the certificate 90 days in advance.
		ServiceName:                  apis.AntreaServiceName,
		PairName:                     "antrea-controller",
	}
}
