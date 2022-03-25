// Copyright 2020 Antrea Authors
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

package v1beta2

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(addConversionFuncs)
}

// addConversionFuncs adds non-generated conversion functions to the given scheme.
func addConversionFuncs(scheme *runtime.Scheme) error {
	for _, kind := range []string{"AppliedToGroup", "AddressGroup", "NetworkPolicy", "EgressGroup", "ExternalEntity"} {
		err := scheme.AddFieldLabelConversionFunc(SchemeGroupVersion.WithKind(kind),
			func(label, value string) (string, string, error) {
				switch label {
				// Antrea Agents select resources by nodeName.
				case "metadata.name", "nodeName":
					return label, value, nil
				default:
					return "", "", fmt.Errorf("field label not supported: %s", label)
				}
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}
