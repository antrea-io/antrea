// Copyright 2022 Antrea Authors
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

package support

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestDumpLog(t *testing.T) {

	basedir := "dir1/dir2"
	fs := afero.NewOsFs()
	since := "6"

	varr := NewAgentDumper(fs, nil, nil, nil, nil, since, true, true)
	err := varr.DumpLog(basedir)

	assert.NoError(t, err)

}
func TestDumpHostNetworkInfo(t *testing.T) {

	basedir := "dir1/dir2"
	fs := afero.NewOsFs()
	since := "6"

	varr := NewAgentDumper(fs, nil, nil, nil, nil, since, true, true)
	err := varr.DumpHostNetworkInfo(basedir)

	assert.NoError(t, err)

}
