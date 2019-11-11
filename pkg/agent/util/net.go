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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	interfaceNameLength   = 15
	podNamePrefixLength   = 8
	containerKeyConnector = `-`
)

// Calculates a suitable interface name using the pod namespace and pod name. The output should be
// deterministic (so that multiple calls to GenerateContainerInterfaceName with the same parameters
// return the same value). The output should have length interfaceNameLength (15). The probability of
// collision should be neglectable.
func GenerateContainerInterfaceName(podName string, podNamespace string) string {
	hash := sha1.New()
	podID := fmt.Sprintf("%s/%s", podNamespace, podName)
	io.WriteString(hash, podID)
	podKey := hex.EncodeToString(hash.Sum(nil))
	name := strings.Replace(podName, "-", "", -1)
	if len(name) > podNamePrefixLength {
		name = name[:podNamePrefixLength]
	}
	podKeyLength := interfaceNameLength - len(name) - len(containerKeyConnector)
	return strings.Join([]string{name, podKey[:podKeyLength]}, containerKeyConnector)
}
