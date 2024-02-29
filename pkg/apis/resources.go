// Copyright 2024 Antrea Authors
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

package apis

const (
	// AntreaCAConfigMapName is the name of the ConfigMap that holds the CA certificate that validates the TLS
	// certificate of antrea-controller.
	AntreaCAConfigMapName = "antrea-ca"

	// AntreaControllerTLSSecretName is the name of the Secret that holds the self-signed TLS certificate and key of
	// antrea-controller.
	AntreaControllerTLSSecretName = "antrea-controller-tls"

	// AntreaServiceName is the name of the Service that exposes antrea-controller.
	AntreaServiceName = "antrea"

	// CAConfigMapKey is the key that holds the CA certificate.
	CAConfigMapKey = "ca.crt"
)
