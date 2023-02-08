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

package e2e

import (
	"log"
	"time"

	antreae2e "antrea.io/antrea/test/e2e"
)

type TestData struct {
	e2eTestData        *antreae2e.TestData
	logsDirForTestCase string
}

const (
	busyboxImage    = "projects.registry.vmware.com/antrea/busybox"
	defaultInterval = 1 * time.Second
)

var testData *TestData

type ClusterInfo struct {
	controlPlaneNodeName string
}

var clusterInfo ClusterInfo

func (data *TestData) createClient(kubeconfigPath string) error {
	e2edata = &antreae2e.TestData{}
	if err := e2edata.CreateClient(kubeconfigPath); err != nil {
		log.Fatalf("Error when creating K8s ClientSet: %v", err)
		return err
	}
	data.e2eTestData = e2edata
	return nil
}
