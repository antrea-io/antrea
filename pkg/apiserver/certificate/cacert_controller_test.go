// Copyright 2022 Antrea Authors
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

package certificate

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	fakeapiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	cgtesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeaggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
)

func TestSyncConfigMap(t *testing.T) {
	existingCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "antrea-ca",
		},
		Data: map[string]string{"ca.crt": "123"},
	}

	tests := []struct {
		name           string
		existingCM     *corev1.ConfigMap
		prepareReactor func(clientset *fakeclientset.Clientset)
		expectedErrMsg string
	}{
		{
			name:           "create antrea-ca ConfigMap successfully",
			prepareReactor: func(clientset *fakeclientset.Clientset) {},
		},
		{
			name: "fail to create antrea-ca ConfigMap",
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("create", "configmaps", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.ConfigMap{}, errors.New("error creating configmap")
				})
			},
			expectedErrMsg: "error creating ConfigMap antrea-ca: error creating configmap",
		},
		{
			name:           "update antrea-ca ConfigMap successfully",
			existingCM:     existingCM,
			prepareReactor: func(clientset *fakeclientset.Clientset) {},
		},
		{
			name:       "fail to update antrea-ca ConfigMap",
			existingCM: existingCM,
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("update", "configmaps", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.ConfigMap{}, errors.New("error updating configmap")
				})
			},
			expectedErrMsg: "error updating ConfigMap antrea-ca: error updating configmap",
		},
		{
			name: "fail to get antrea-ca ConfigMap",
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("get", "configmaps", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.ConfigMap{}, errors.New("error getting configmap")
				})
			},
			expectedErrMsg: "error getting ConfigMap antrea-ca: error getting configmap",
		},
	}
	caConfig := &CAConfig{
		ServiceName:     AntreaServiceName,
		PairName:        "antrea-controller",
		CAConfigMapName: "antrea-ca",
	}
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	var err error
	caConfig.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-self-signed")
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(caConfig.SelfSignedCertDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			if tt.existingCM != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingCM)
			}
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
			caContentProvider, _ := generateSelfSignedCertificate(secureServing, caConfig)
			tt.prepareReactor(clientset)

			controller := newCACertController(caContentProvider, clientset, aggregatorClientset, apiExtensionClient, caConfig)
			err := controller.syncConfigMap([]byte("abc"))
			if tt.expectedErrMsg != "" {
				require.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "antrea-ca", metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, "abc", cm.Data["ca.crt"])
		})
	}
}

func TestSyncAPIServices(t *testing.T) {
	existingAPIService := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v1alpha1.stats.antrea.io",
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Service: &apiregistrationv1.ServiceReference{
				Namespace: "kube-system",
				Name:      "antrea",
			},
			CABundle: []byte("def"),
		},
	}
	tests := []struct {
		name               string
		existingAPIService *apiregistrationv1.APIService
		prepareReactor     func(clientset *fakeaggregatorclientset.Clientset)
		expectedErrMsg     string
	}{
		{
			name:               "sync API Service successfully",
			existingAPIService: existingAPIService,
			prepareReactor:     func(clientset *fakeaggregatorclientset.Clientset) {},
		},
		{
			name:           "fail to get API Service",
			prepareReactor: func(clientset *fakeaggregatorclientset.Clientset) {},
			expectedErrMsg: "error getting APIService v1alpha1.stats.antrea.io: apiservices.apiregistration.k8s.io \"v1alpha1.stats.antrea.io\" not found",
		},
		{
			name:               "fail to update API Service",
			existingAPIService: existingAPIService,
			prepareReactor: func(clientset *fakeaggregatorclientset.Clientset) {
				clientset.PrependReactor("update", "apiservices", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &apiregistrationv1.APIService{}, errors.New("error updating APIService")
				})
			},
			expectedErrMsg: "error updating antrea CA cert of APIService v1alpha1.stats.antrea.io: error updating APIService",
		},
	}
	caConfig := &CAConfig{
		ServiceName:     AntreaServiceName,
		PairName:        "antrea-controller",
		CAConfigMapName: "antrea-ca",
		APIServiceNames: []string{
			"v1alpha1.stats.antrea.io",
		},
	}
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	var err error
	caConfig.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-self-signed")
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(caConfig.SelfSignedCertDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
			caContentProvider, _ := generateSelfSignedCertificate(secureServing, caConfig)

			if tt.existingAPIService != nil {
				aggregatorClientset = fakeaggregatorclientset.NewSimpleClientset(tt.existingAPIService)
			}
			tt.prepareReactor(aggregatorClientset)

			controller := newCACertController(caContentProvider, clientset, aggregatorClientset, apiExtensionClient, caConfig)
			caBundle := []byte("abc")
			err = controller.syncAPIServices(caBundle)
			if tt.expectedErrMsg != "" {
				require.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			apiService, err := aggregatorClientset.ApiregistrationV1().APIServices().Get(context.Background(), "v1alpha1.stats.antrea.io", metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, caBundle, apiService.Spec.CABundle)
		})
	}
}

func TestSyncValidatingWebhooks(t *testing.T) {
	existingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "crdvalidator.antrea.io",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "acnpmutator.antrea.io",
			},
		},
	}

	tests := []struct {
		name            string
		existingWebhook *admissionregistrationv1.ValidatingWebhookConfiguration
		prepareReactor  func(clientset *fakeclientset.Clientset)
		expectedErrMsg  string
	}{
		{
			name:            "sync webhook successfully",
			existingWebhook: existingWebhook,
			prepareReactor:  func(clientset *fakeclientset.Clientset) {},
		},
		{
			name:           "fail to get webhook",
			prepareReactor: func(clientset *fakeclientset.Clientset) {},
			expectedErrMsg: "error getting ValidatingWebhookConfiguration crdvalidator.antrea.io: validatingwebhookconfigurations.admissionregistration.k8s.io \"crdvalidator.antrea.io\" not found",
		},
		{
			name:            "fail to update webhook",
			existingWebhook: existingWebhook,
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("update", "validatingwebhookconfigurations", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &admissionregistrationv1.ValidatingWebhookConfiguration{}, errors.New("error updating validatingwebhookconfigurations")
				})
			},
			expectedErrMsg: "error updating antrea CA cert of ValidatingWebhookConfiguration crdvalidator.antrea.io: error updating validatingwebhookconfigurations",
		},
	}
	caConfig := &CAConfig{
		ServiceName:     AntreaServiceName,
		PairName:        "antrea-controller",
		CAConfigMapName: "antrea-ca",
		ValidatingWebhooks: []string{
			"crdvalidator.antrea.io",
		},
	}
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	var err error
	caConfig.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-self-signed")
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(caConfig.SelfSignedCertDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
			caContentProvider, _ := generateSelfSignedCertificate(secureServing, caConfig)

			if tt.existingWebhook != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingWebhook)
			}
			tt.prepareReactor(clientset)
			controller := newCACertController(caContentProvider, clientset, aggregatorClientset, apiExtensionClient, caConfig)
			caBundle := []byte("abc")
			err = controller.syncValidatingWebhooks(caBundle)
			if tt.expectedErrMsg != "" {
				require.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			vWebhook, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "crdvalidator.antrea.io", metav1.GetOptions{})
			require.NoError(t, err)
			for _, webhook := range vWebhook.Webhooks {
				assert.Equal(t, caBundle, webhook.ClientConfig.CABundle)
			}
		})
	}
}

func TestSyncMutatingWebhooks(t *testing.T) {
	existingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "crdmutator.antrea.io",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "acnpmutator.antrea.io",
			},
		},
	}
	existingOptionalWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labelsmutator.antrea.io",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "abcmutator.antrea.io",
			},
		},
	}

	tests := []struct {
		name             string
		existingWebhooks []*admissionregistrationv1.MutatingWebhookConfiguration
		prepareReactor   func(clientset *fakeclientset.Clientset)
		expectedErrMsg   string
		skipOptional     bool
	}{
		{
			name:             "sync webhook successfully",
			existingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{existingWebhook, existingOptionalWebhook},
			prepareReactor:   func(clientset *fakeclientset.Clientset) {},
		},
		{
			name:           "fail to get mutating webhook",
			prepareReactor: func(clientset *fakeclientset.Clientset) {},
			expectedErrMsg: "error getting MutatingWebhookConfiguration crdmutator.antrea.io: mutatingwebhookconfigurations.admissionregistration.k8s.io \"crdmutator.antrea.io\" not found",
		},
		{
			name:             "skip sync optional mutating webhook",
			existingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{existingWebhook},
			prepareReactor:   func(clientset *fakeclientset.Clientset) {},
			skipOptional:     true,
		},
		{
			name:             "fail to get optional webhook",
			existingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{existingWebhook},
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("get", "mutatingwebhookconfigurations", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					if action.(cgtesting.GetAction).GetName() == "labelsmutator.antrea.io" {
						err = errors.New("error getting mutatingwebhookconfigurations labelsmutator.antrea.io")
					}
					return true, &admissionregistrationv1.MutatingWebhookConfiguration{}, err
				})
			},
			expectedErrMsg: "error getting MutatingWebhookConfiguration labelsmutator.antrea.io: error getting mutatingwebhookconfigurations labelsmutator.antrea.io",
		},
		{
			name:             "fail to update webhook",
			existingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{existingWebhook},
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("update", "mutatingwebhookconfigurations", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &admissionregistrationv1.MutatingWebhookConfiguration{}, errors.New("error updating mutatingwebhookconfigurations crdmutator.antrea.io")
				})
			},
			expectedErrMsg: "error updating antrea CA cert of MutatingWebhookConfiguration crdmutator.antrea.io: error updating mutatingwebhookconfigurations crdmutator.antrea.io",
		},
		{
			name:             "fail to update optional webhook",
			existingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{existingWebhook, existingOptionalWebhook},
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("update", "mutatingwebhookconfigurations", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					webhook := action.(cgtesting.UpdateAction).GetObject().(*admissionregistrationv1.MutatingWebhookConfiguration)
					if webhook.ObjectMeta.Name == "labelsmutator.antrea.io" {
						err = errors.New("error updating mutatingwebhookconfigurations labelsmutator.antrea.io")
					}
					return true, &admissionregistrationv1.MutatingWebhookConfiguration{}, err
				})
			},
			expectedErrMsg: "error updating antrea CA cert of MutatingWebhookConfiguration labelsmutator.antrea.io: error updating mutatingwebhookconfigurations labelsmutator.antrea.io",
		},
	}
	caConfig := &CAConfig{
		ServiceName:     AntreaServiceName,
		PairName:        "antrea-controller",
		CAConfigMapName: "antrea-ca",
		MutationWebhooks: []string{
			"crdmutator.antrea.io",
		},
		OptionalMutationWebhooks: []string{
			"labelsmutator.antrea.io",
		},
	}
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	var err error
	caConfig.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-self-signed")
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(caConfig.SelfSignedCertDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
			caContentProvider, _ := generateSelfSignedCertificate(secureServing, caConfig)
			var objects []runtime.Object
			for _, webhook := range tt.existingWebhooks {
				objects = append(objects, webhook)
			}
			clientset := fakeclientset.NewSimpleClientset(objects...)
			tt.prepareReactor(clientset)

			controller := newCACertController(caContentProvider, clientset, aggregatorClientset, apiExtensionClient, caConfig)
			caBundle := []byte("abc")
			err = controller.syncMutatingWebhooks(caBundle)
			if tt.expectedErrMsg != "" {
				require.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			webhooks := []string{"crdmutator.antrea.io", "labelsmutator.antrea.io"}
			if tt.skipOptional {
				webhooks = []string{"crdmutator.antrea.io"}
			}
			for _, name := range webhooks {
				vWebhook, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), name, metav1.GetOptions{})
				require.NoError(t, err)
				for _, webhook := range vWebhook.Webhooks {
					assert.Equal(t, caBundle, webhook.ClientConfig.CABundle)
				}
			}
		})
	}
}

func TestSyncConversionWebhooks(t *testing.T) {
	existingCRD := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clustergroups.crd.antrea.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{
					ClientConfig: &apiextensionsv1.WebhookClientConfig{
						CABundle: []byte("123"),
					},
				},
			},
		},
	}

	tests := []struct {
		name           string
		existingCRD    *apiextensionsv1.CustomResourceDefinition
		prepareReactor func(clientset *fakeapiextensionclientset.Clientset)
		expectedErrMsg string
	}{
		{
			name:           "sync crd webhook successfully",
			existingCRD:    existingCRD,
			prepareReactor: func(clientset *fakeapiextensionclientset.Clientset) {},
		},
		{
			name:           "fail to get crd webhook",
			prepareReactor: func(clientset *fakeapiextensionclientset.Clientset) {},
			expectedErrMsg: "error getting CRD definition for clustergroups.crd.antrea.io: customresourcedefinitions.apiextensions.k8s.io \"clustergroups.crd.antrea.io\" not found",
		},
		{
			name: "fail to sync crd webhook with empty webhook",
			existingCRD: &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "clustergroups.crd.antrea.io"},
			},
			prepareReactor: func(clientset *fakeapiextensionclientset.Clientset) {},
			expectedErrMsg: "CRD clustergroups.crd.antrea.io does not have webhook conversion registered",
		},
		{
			name:        "fail to update crd webhook",
			existingCRD: existingCRD,
			prepareReactor: func(clientset *fakeapiextensionclientset.Clientset) {
				clientset.PrependReactor("update", "customresourcedefinitions", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &apiextensionsv1.CustomResourceDefinition{}, errors.New("error updating customresourcedefinitions")
				})
			},
			expectedErrMsg: "error updating antrea CA cert of CustomResourceDefinition clustergroups.crd.antrea.io: error updating customresourcedefinitions",
		},
	}
	caConfig := &CAConfig{
		ServiceName:                AntreaServiceName,
		PairName:                   "antrea-controller",
		CAConfigMapName:            "antrea-ca",
		CRDsWithConversionWebhooks: []string{"clustergroups.crd.antrea.io"},
	}
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	var err error
	caConfig.SelfSignedCertDir, err = os.MkdirTemp("", "antrea-self-signed")
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(caConfig.SelfSignedCertDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
			caContentProvider, _ := generateSelfSignedCertificate(secureServing, caConfig)

			if tt.existingCRD != nil {
				apiExtensionClient = fakeapiextensionclientset.NewSimpleClientset(tt.existingCRD)
			}
			tt.prepareReactor(apiExtensionClient)
			controller := newCACertController(caContentProvider, clientset, aggregatorClientset, apiExtensionClient, caConfig)
			caBundle := []byte("abc")
			err = controller.syncConversionWebhooks(caBundle)
			if tt.expectedErrMsg != "" {
				require.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			crd, err := apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Get(context.Background(), "clustergroups.crd.antrea.io", metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, caBundle, crd.Spec.Conversion.Webhook.ClientConfig.CABundle)
		})
	}
}
