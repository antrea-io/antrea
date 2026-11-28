// Copyright 2026 Antrea Authors.
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

package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/antctl/raw/check"
)

func TestUncertainError(t *testing.T) {
	err := newUncertainError("warning: %s", "something uncertain")
	assert.Equal(t, "warning: something uncertain", err.Error())
}

func TestNewOptions(t *testing.T) {
	opts := newOptions()
	assert.Equal(t, check.DefaultTestImage, opts.testImage)
}

func TestCommand(t *testing.T) {
	cmd := Command()
	assert.Equal(t, "cluster", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	flag := cmd.Flags().Lookup("test-image")
	assert.NotNil(t, flag)
	assert.Equal(t, check.DefaultTestImage, flag.DefValue)
}
