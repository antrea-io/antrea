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

	"github.com/stretchr/testify/assert"
)

func TestReplaceFieldValue(t *testing.T) {
	content := `
#  featureGateField0:
#field0:
# field1: abc
`
	cs := []configChange{
		{"featureGateField0", "123", true},
		{"field0", "456", false},
		{"field1", "789", false},
	}
	expected := `
  featureGateField0: 123
field0: 456
field1: 789
`
	for _, c := range cs {
		content = replaceFieldValue(content, c)
	}
	assert.Equal(t, expected, content)
}
