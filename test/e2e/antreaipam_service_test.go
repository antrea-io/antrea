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
	"testing"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
)

func TestAntreaIPAMService(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	ippool, err := createIPPool(t, data, 0)
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ippool.Name)
	annotations := map[string]string{}
	annotations[ipam.AntreaIPAMAnnotationKey] = ippool.Name
	err = data.createNamespaceWithAnnotations(testAntreaIPAMNamespace, annotations)
	if err != nil {
		t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
	}
	defer deleteAntreaIPAMNamespace(t, data)

	t.Run("testAntreaIPAMClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace)
	})
}
