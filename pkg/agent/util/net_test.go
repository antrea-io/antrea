// Copyright 2019 Antrea Authors
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

package util

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateContainerInterfaceName(t *testing.T) {
	podNamespace := "namespace1"
	podName0 := "pod0"
	iface0 := GenerateContainerInterfaceName(podName0, podNamespace)
	if len(iface0) > interfaceNameLength {
		t.Errorf("Failed to ensure length of interface name %s <= %d", iface0, interfaceNameLength)
	}
	if !strings.HasPrefix(iface0, fmt.Sprintf("%s-", podName0)) {
		t.Errorf("failed to use podName as prefix: %s", iface0)
	}
	podName1 := "pod1-abcde-12345"
	iface1 := GenerateContainerInterfaceName(podName1, podNamespace)
	if len(iface1) != interfaceNameLength {
		t.Errorf("Failed to ensure length of interface name as %d", interfaceNameLength)
	}
	if !strings.HasPrefix(iface1, "pod1-abc") {
		t.Errorf("failed to use first 8 valid characters")
	}
	podName2 := "pod1-abcde-54321"
	iface2 := GenerateContainerInterfaceName(podName2, podNamespace)
	if iface1 == iface2 {
		t.Errorf("failed to differentiate interfaces with pods has the same prefix")
	}
}
