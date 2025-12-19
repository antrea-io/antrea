// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowexporter

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	CAConfigMapNamespace  = "flow-aggregator"
	CAConfigMapName       = "flow-aggregator-ca"
	CAConfigMapKey        = "ca.crt"
	ClientSecretNamespace = "flow-aggregator"
	// #nosec G101: false positive triggered by variable name which includes "Secret"
	ClientSecretName = "flow-aggregator-client-tls"
)

func getCACert(ctx context.Context, k8sClient kubernetes.Interface, namespace, name string) ([]byte, error) {
	caConfigMap, err := k8sClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting ConfigMap %s: %v", name, err)
	}
	if caConfigMap.Data == nil || caConfigMap.Data[CAConfigMapKey] == "" {
		return nil, fmt.Errorf("no data in %s ConfigMap", name)
	}
	return []byte(caConfigMap.Data[CAConfigMapKey]), nil
}

func getClientCertKey(ctx context.Context, k8sClient kubernetes.Interface, namespace, name string) ([]byte, []byte, error) {
	clientSecret, err := k8sClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Secret %s: %v", name, err)
	}
	if clientSecret.Data == nil || clientSecret.Data["tls.crt"] == nil || clientSecret.Data["tls.key"] == nil {
		return nil, nil, fmt.Errorf("error getting data from Secret %s: %v", name, err)
	}
	return clientSecret.Data["tls.crt"], clientSecret.Data["tls.key"], nil
}
