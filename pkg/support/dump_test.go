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

package support

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLogDate(t *testing.T) {
	data := "I0817 06:55:10.804384       1 shared_informer.go:270] caches populated"
	ts, err := parseTimeFromLogLine(data, "2021", "antrea-agent")
	assert.Nil(t, err)
	assert.Equal(t, ts.String(), "2021-08-17 06:55:10 +0000 UTC")

	data = "2021-06-01T09:30:43.823Z|00004|memory|INFO|cells:299 monitors:2 sessions:2"
	ts, err = parseTimeFromLogLine(data, "2021", "ovs")
	assert.Nil(t, err)
	assert.Equal(t, ts.String(), "2021-06-01 09:30:43 +0000 UTC")
}

func TestParseFileName(t *testing.T) {
	name := "antrea-agent.ubuntu-1.root.log.WARNING.20210817-094758.1"
	ts, err := parseTimeFromFileName(name)
	assert.Nil(t, err)
	assert.Equal(t, ts.String(), "2021-08-17 09:47:58 +0000 UTC")
}
