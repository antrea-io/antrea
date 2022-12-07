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

package compress

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

var testFS = new(afero.MemMapFs)

func TestPackDir(t *testing.T) {
	basedir, err := afero.TempDir(testFS, "", "bundle_tmp_")
	assert.NoError(t, err)
	defer testFS.RemoveAll(basedir)

	outputFile, err := afero.TempFile(testFS, "", "bundle_*.tar.gz")
	assert.NoError(t, err)
	defer outputFile.Close()

	_, err = PackDir(testFS, basedir, outputFile)
	assert.NoError(t, err)
	_, err = PackDir(testFS, "/noexist", outputFile)
	assert.Error(t, err)
}
