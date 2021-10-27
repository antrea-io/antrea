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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestConfigChange(t *testing.T) {
	content := `
featureGates:
#  featureGateField0:
#field0:
# field1: abc
field2:
  nestedField: 7
`

	changeField2 := func(content string) string {
		var cfg interface{}
		require.NoError(t, yaml.Unmarshal([]byte(content), &cfg))
		newField := map[string]interface{}{
			"nestedField":  8,
			"nestedField2": true,
		}
		cfg.(map[interface{}]interface{})["field2"] = newField
		b, err := yaml.Marshal(&cfg)
		require.NoError(t, err)
		return string(b)
	}

	cgs := []configChange{
		&configChangeFeatureGate{"featureGateField0", true},
		&configChangeParam{"field0", "456"},
		&configChangeParam{"field1", "789"},
		&configChangeRaw{changeField2},
	}
	expected := `
featureGates:
  featureGateField0: true
field0: 456
field1: 789
field2:
  nestedField: 8
  nestedField2: true
`
	for _, cg := range cgs {
		content = cg.ApplyChange(content)
	}
	assert.Equal(t, strings.TrimSpace(expected), strings.TrimSpace(content))
}
