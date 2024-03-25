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

package flowaggregator

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetk8sClient(t *testing.T) {
	tcs := []struct {
		name        string
		fakeConfigs []byte
		expectedErr string
	}{
		{
			name: "invalid kubeconfig",
			fakeConfigs: []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: data
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`),
			expectedErr: "failed to create K8s clientset: unable to load root certificates: unable to parse bytes as PEM block",
		},
		{
			name: "valid kubeconf",
			fakeConfigs: []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJTHJac3Z6ZFQ3ekF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TWpBNE1qSXdNakl6TXpkYUZ3MHlNekE0TWpJd01qSXpNemxhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTB4N2JEd2NqSzN3VjRGSzkKYUtrd0FUdjVoT2NsbHhUSEI1ejFUbHZJV3pmdTNYNjZtaWkxUE04ODI1dTArdDRRdisxUVRIRHFzUkNvWFA1awpuNGNWZkxkeTlad25uN01uSDExVTRsRWRoeXBrdlZsc0RmajlBdWh3WHBZVE82eE5kM2o2Y3BIZGNMOW9PbGw2CkowcGU2RzBleHpTSHMvbHRUZXlyalRGbXM2Sm5zSWV6T2lHRmhZOTJCbDBmZ1krb2p6MFEwM2cvcE5QZUszcGMKK05wTWh4eG1UY1lVNzlaZVRqV1JPYTFQSituNk1SMEhDbW0xQk5QNmdwWmozbGtWSktkZnBEYmovWHYvQWNkVQpab3E5Ym95aGNDUCtiYmgyaWVtaTc0bnZqZ1BUTkVDZWU2a3ZHY3VNaXRKUkdvWjBxbFpZbXZDaWdEeGlSTnBNClBPa1dud0lEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JSc2VoZXVkM0l5VWRNdkhhRS9YU3MrOFErLwpiVEFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBcmg4UFRadFgvWjlHVzlMYmxZZ1FWWE04VlRrWEtGSEpTZldOCkJLNXo2NWNWdGN2cFZ0WDZNTlppTFhuYkFzQ0JPY1RqejBJRlphYkNNUkZzYmdYbEVqV0ZuRE5abzBMVHFTZUcKQ2RqTWljK0JzbmFGUThZOXJ5TTVxZ0RhQzNWQkdTSXVscklXeGxPYmRmUEpWRnpUaVNTcmJBR1Z3Uk5sQlpmYgpYOXBlRlpNNmNFNUhTOE5RTmNoZkh2SWhGSUVuR2YxOUx2enp0WGUzQWwwb3hYNjdRKzhyWXd0Tm56dS9xM29BCmJIN1dsNld5ODVYNS90RWlQcWU0ZU1GalRDME9tR2NHZ2lQdU90NjlIejAwV2hvaWNYYWpma1FZOHNKMk5Uc1cKdUcxbWZqb0tTdUN0OC9BRmhPNURlaHZ3eFNIQU12eG1VQUJYL294bU1DNzdwV0VnRWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewFlowAggregatorSetCommand()
			fakeKubeconfig, err := os.CreateTemp("", "fakeKubeconfig")
			if err != nil {
				t.Fatalf("Failed to create temp kubeconfig: %v", err)
			}
			defer os.Remove(fakeKubeconfig.Name())
			fakeKubeconfig.Write(tc.fakeConfigs)
			cmd.Flags().String("kubeconfig", fakeKubeconfig.Name(), "path of kubeconfig")
			_, err = getk8sClient(cmd)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}

func TestUpdateRunE(t *testing.T) {
	fakeConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testConfigMap",
			Namespace: "flow-aggregator",
		},
	}

	k8sClient := fake.NewSimpleClientset(fakeConfigMap)
	tcs := []struct {
		name           string
		configMapName  string
		podNamespace   string
		args           []string
		expectedErr    string
		expectedOutput map[string]string
	}{
		{
			name:           "valid ConfigMap and nil args",
			configMapName:  "testConfigMap",
			podNamespace:   "flow-aggregator",
			expectedOutput: map[string]string{"flow-aggregator.conf": "{}\n"},
		},
		{
			name:          "invalid ConfigMap and nil args",
			configMapName: "",
			podNamespace:  "flow-aggregator",
			expectedErr:   "failed to locate flow-aggregator-config ConfigMap volume",
		},
		{
			name:           "valid ConfigMap and valid args",
			configMapName:  "testConfigMap",
			podNamespace:   "flow-aggregator",
			args:           []string{"clickHouse.enable=true"},
			expectedOutput: map[string]string{"flow-aggregator.conf": "clickHouse:\n  enable: true\n"},
		},
		{
			name:          "valid ConfigMap and invalid args",
			configMapName: "testConfigMap",
			podNamespace:  "flow-aggregator",
			args:          []string{"clickhouse=true"},
			expectedErr:   "unknown configuration parameter, please check antctl set flow-aggregator -h",
		},
		{
			name:          "valid ConfigMap and invalid args syntax",
			configMapName: "testConfigMap",
			podNamespace:  "flow-aggregator",
			args:          []string{"clickhouse.enable=true clickhopuse.debug=true"},
			expectedErr:   "query should contain exactly one '='",
		},
		{
			name:          "wrong Pod Namespace",
			configMapName: "testConfigMap",
			podNamespace:  "flow-visibility",
			expectedErr:   "request namespace does not match object namespace",
		},
	}

	getClients = func(cmd *cobra.Command) (kubernetes.Interface, error) {
		return k8sClient, nil
	}
	defer func() {
		getClients = getk8sClient
	}()

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewFlowAggregatorSetCommand()
			t.Setenv("POD_NAMESPACE", tc.podNamespace)
			t.Setenv("FA_CONFIG_MAP_NAME", tc.configMapName)
			err := updateRunE(cmd, tc.args)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				cm, _ := k8sClient.CoreV1().ConfigMaps(os.Getenv("POD_NAMESPACE")).Get(context.TODO(), fakeConfigMap.Name, metav1.GetOptions{})
				assert.Equal(t, tc.expectedOutput, cm.Data)
			}
		})
	}
}

func TestSetBoolOrFail(t *testing.T) {
	tcs := []struct {
		name          string
		value         string
		expectedValue bool
		expectedErr   string
	}{
		{
			name:          "true boolean value",
			value:         "1",
			expectedValue: true,
		},
		{
			name:          "false boolean value",
			value:         "f",
			expectedValue: false,
		},
		{
			name:        "invalid value",
			value:       "tt",
			expectedErr: "invalid syntax",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var actualValue bool
			err := setBoolOrFail(&actualValue, tc.value)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedValue, actualValue)
			}
		})
	}
}

func TestSetStringOrFail(t *testing.T) {
	var actualValue string
	value := "11mm"

	err := setStringOrFail(&actualValue, value)
	assert.NoError(t, err)
	assert.Equal(t, value, actualValue)
}

func TestSetCommitIntervalOrFail(t *testing.T) {
	tcs := []struct {
		name        string
		value       string
		expectedErr string
	}{
		{
			name:  "valid commit interval",
			value: "1m25s",
		},
		{
			name:        "very short commit interval",
			value:       "0.5s",
			expectedErr: "commitInterval 500ms is too small: shortest supported interval is",
		},
		{
			name:        "invalid value string",
			value:       "0.5ss",
			expectedErr: "time: unknown unit",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var actualValue string
			err := setCommitIntervalOrFail(&actualValue, tc.value)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.value, actualValue)
			}
		})
	}
}

func TestGetFAConfigMap(t *testing.T) {
	fakeConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testConfigMap",
			Namespace: "flow-aggregator",
		},
	}

	k8sClient := fake.NewSimpleClientset(fakeConfigMap)
	tcs := []struct {
		name          string
		configMapName string
		expectedErr   string
	}{
		{
			name:          "get ConfigMap successfully",
			configMapName: "testConfigMap",
		},
		{
			name:          "empty ConfigMap name",
			configMapName: "",
			expectedErr:   "failed to locate flow-aggregator-config ConfigMap volume",
		},
		{
			name:          "non existing ConfigMap",
			configMapName: "testConfigMap1",
			expectedErr:   "failed to get ConfigMap testConfigMap1",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := GetFAConfigMap(k8sClient, tc.configMapName)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, fakeConfigMap, cm)
			}
		})
	}
}
