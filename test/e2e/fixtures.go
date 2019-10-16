// Copyright 2019 OKN Authors
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

package e2e

import (
	"testing"
)

func setupTest(t *testing.T) (*TestData, error) {
	data := &TestData{}
	t.Logf("Creating K8s clientset")
	// TODO: it is probably not needed to re-create the clientset in each test, maybe we could
	// just keep it in clusterInfo?
	if err := data.createClient(); err != nil {
		return nil, err
	}
	t.Logf("Creating '%s' K8s Namespace", testNamespace)
	if err := data.createTestNamespace(); err != nil {
		return nil, err
	}
	t.Logf("Applying OKN YAML")
	if err := data.deployOKN(); err != nil {
		return nil, err
	}
	t.Logf("Waiting for all OKN DaemonSet Pods")
	if err := data.waitForOKNDaemonSetPods(defaultTimeout); err != nil {
		return nil, err
	}
	// TODO: CoreDNS keeps crashing at the moment, even when OKN is running fine.
	// t.Logf("Checking CoreDNS deployment")
	// if err := data.checkCoreDNSPods(defaultTimeout); err != nil {
	// 	return nil, err
	// }
	return data, nil
}

func teardownTest(t *testing.T, data *TestData) {
	t.Logf("Deleting '%s' K8s Namespace", testNamespace)
	if err := data.deleteTestNamespace(defaultTimeout); err != nil {
		t.Logf("Error when tearing down test: %v", err)
	}
}

func deletePodWrapper(t *testing.T, data *TestData, name string) {
	t.Logf("Deleting Pod '%s'", name)
	if err := data.deletePod(name); err != nil {
		t.Logf("Error when deleting Pod: %v", err)
	}
}
