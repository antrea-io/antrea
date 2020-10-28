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

package ovsconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOVSClient(t *testing.T) {
	_, err := parseOvsVersion(nil)
	assert.Error(t, err)

	// raw strings are not accepted, we want to make sure the function doesn't panic and returns an error
	_, err = parseOvsVersion("ovs_version")
	assert.Error(t, err)

	m1 := map[string]string{"ovs_version": "1"}
	_, err = parseOvsVersion(m1)
	assert.NoError(t, err)

	m2 := map[string]interface{}{"ovs_version": "1.2.3.4.5"}
	_, err = parseOvsVersion(m2)
	assert.NoError(t, err)

}
