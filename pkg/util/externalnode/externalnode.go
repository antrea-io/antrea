// Copyright 2022 Antrea Authors
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

package externalnode

import (
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"fmt"
	"io"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const interfaceNameLength = 5

func GenExternalEntityName(externalNode *v1alpha1.ExternalNode) (string, error) {
	if len(externalNode.Spec.Interfaces) == 0 {
		// This should not happen since openAPIV3Schema checks it.
		return "", fmt.Errorf("failed to get interface from ExternalNode %s", externalNode.Name)
	}
	// Only one network interface is supported now.
	// Other interfaces except interfaces[0] will be ignored if there are more than one interfaces.
	ifName := externalNode.Spec.Interfaces[0].Name
	if ifName == "" {
		return externalNode.Name, nil
	} else {
		hash := sha1.New() // #nosec G401: not used for security purposes
		io.WriteString(hash, ifName)
		hashedIfName := hex.EncodeToString(hash.Sum(nil))
		return externalNode.Name + "-" + hashedIfName[:interfaceNameLength], nil
	}
}
