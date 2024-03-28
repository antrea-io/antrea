// Copyright 2021 Antrea Authors
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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CAConfig struct {
	// Name of the ConfigMap that will hold the CA certificate that validates the TLS
	// certificate of antrea-controller.
	CAConfigMapName string

	// Name of the Secret that will hold the self-signed TLS certificate and key of antrea-controller.
	// If set, the certificate and key will be stored in the Secret for future reuse.
	TLSSecretName string

	// APIServiceSelector provides the label to select APIServices backed by antrea-controller. Using labels as a filter
	// to select APIServices is more flexible than maintaining a list of APIService names, e.g., cluster admin can remove
	// unneeded APIServices in a setup without Antrea code changes.
	APIServiceSelector *metav1.LabelSelector

	// ValidatingWebhookSelector provides the label to select ValidatingWebhookConfigurations backed by antrea-controller.
	ValidatingWebhookSelector *metav1.LabelSelector

	// MutationWebhookSelector provides the label to select MutatingWebhookConfigurations backed by antrea-controller.
	MutationWebhookSelector *metav1.LabelSelector

	// CRDConversionWebhookSelector provides the label to select the ConversionWebhooks backed by antrea-controller.
	CRDConversionWebhookSelector *metav1.LabelSelector

	// CertDir is the directory that the TLS Secret should be mounted to. Declaring it as a variable for testing.
	CertDir string

	// SelfSignedCertDir is the dir Antrea self signed certificates are created in.
	SelfSignedCertDir string

	// CertReadyTimeout is the timeout we will wait for the TLS Secret being ready. Declaring it as a variable for testing.
	CertReadyTimeout time.Duration

	// MinValidDuration is the minimal remaining valid duration for the self-signed certificate. It must be rotated once
	// the time until the certificate expires becomes shorter than this duration.
	MinValidDuration time.Duration
	ServiceName      string
	PairName         string
}
