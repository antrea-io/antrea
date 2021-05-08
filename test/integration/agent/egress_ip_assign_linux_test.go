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

package agent

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/controller/egress"
	"antrea.io/antrea/pkg/agent/controller/egress/ipassigner"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

const defaultEgressRunDir = egress.DefaultEgressRunDir

func TestEgressIPAssigner(t *testing.T) {
	ipAssigner, err := ipassigner.NewIPAssigner(nodeIP.IP, defaultEgressRunDir)
	if err != nil {
		t.Fatalf("Initializing egressIP assigner failed: %v", err)
	}

	egressName := "test-egress"
	egressIP := "10.10.10.10"
	eg := &v1alpha2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: egressName},
		Spec:       v1alpha2.EgressSpec{EgressIP: egressIP},
	}
	assignErr := ipAssigner.AssignEgressIP("", eg.Name)
	assert.Error(t, assignErr, "invalid IP ")
	assignErr = ipAssigner.AssignEgressIP("x", eg.Name)
	assert.Error(t, assignErr, "invalid IP x")
	// Assign EgressIP.
	if err := ipAssigner.AssignEgressIP(eg.Spec.EgressIP, eg.Name); err != nil {
		t.Fatalf("Assigning egress IP error: %v", err)
	}

	ips := ipAssigner.AssignedIPs()
	assert.Equal(t, ips, map[string]string{eg.Name: eg.Spec.EgressIP}, "List assigned IPs not match")

	readEgressIPFile := func(egressName string) string {
		fileName := strings.Join([]string{defaultEgressRunDir, egressName}, "/")
		ipStr, err := ioutil.ReadFile(fileName)
		if err != nil {
			return ""
		}
		return string(ipStr)
	}
	assert.Equal(t, eg.Spec.EgressIP, readEgressIPFile(eg.Name), "Reading IP assigned file not match")

	// Unassign EgressIP.
	if err := ipAssigner.UnassignEgressIP(eg.Name); err != nil {
		t.Fatalf("Unassigning egress IP error: %v", err)
	}

	ips = ipAssigner.AssignedIPs()
	assert.Equal(t, map[string]string{}, ips, "List assigned IPs not match")
}
