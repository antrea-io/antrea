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

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func createDirectory(path string) error {
	return os.Mkdir(path, 0700)
}

func (data *TestData) setupLogDirectoryForTest(testName string) error {
	path := filepath.Join(testOptions.logsExportDir, testName)
	// remove directory if it already exists. This ensures that we start with an empty
	// directory
	_ = os.RemoveAll(path)
	err := createDirectory(path)
	if err != nil {
		return err
	}
	data.logsDirForTestCase = path
	return nil
}

func setupTest(tb testing.TB) (*TestData, error) {
	if err := testData.setupLogDirectoryForTest(tb.Name()); err != nil {
		tb.Errorf("Error creating logs directory '%s': %v", testData.logsDirForTestCase, err)
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			tb.Fail()
		}
	}()
	tb.Logf("Creating '%s' K8s Namespace", multiClusterTestNamespace)
	if err := testData.createTestNamespace(); err != nil {
		return nil, err
	}

	success = true
	return testData, nil
}

func teardownTest(tb testing.TB, data *TestData) {
	if empty, _ := IsDirEmpty(data.logsDirForTestCase); empty {
		_ = os.Remove(data.logsDirForTestCase)
	}
}

func createPodWrapper(tb testing.TB, data *TestData, cluster string, namespace string, name string, image string, ctr string, command []string,
	args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(pod *corev1.Pod)) error {
	tb.Logf("Creating Pod '%s'", name)
	if err := data.createPod(cluster, name, namespace, ctr, image, command, args, env, ports, hostNetwork, mutateFunc); err != nil {
		return err
	}

	_, err := data.podWaitFor(defaultTimeout, westCluster, name, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})

	return err
}

func deletePodWrapper(tb testing.TB, data *TestData, clusterName string, namespace string, name string) {
	tb.Logf("Deleting Pod '%s'", name)
	if err := data.deletePod(clusterName, namespace, name); err != nil {
		tb.Logf("Error when deleting Pod: %v", err)
	}
}

func deleteServiceWrapper(tb testing.TB, data *TestData, clusterName string, namespace string, name string) {
	tb.Logf("Deleting Service '%s'", name)
	if err := data.deleteService(clusterName, namespace, name); err != nil {
		tb.Logf("Error when deleting Service: %v", err)
	}
}
