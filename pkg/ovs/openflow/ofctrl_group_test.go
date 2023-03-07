// Copyright 2023 Antrea Authors.
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

package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
)

func TestGroup(t *testing.T) {
	group := &ofctrl.Group{
		ID:      uint32(1),
		Buckets: []*openflow15.Bucket{},
	}
	bktBuilder := bucketBuilder{
		group: &ofGroup{
			ofctrl: group,
		},
		bucket: &openflow15.Bucket{},
	}
	bktBuilder.Group(2)
	expectedActionGroup, _ := openflow15.NewActionGroup(2).MarshalBinary()
	actual, _ := bktBuilder.bucket.Actions[0].MarshalBinary()
	assert.Equal(t, expectedActionGroup, actual)
}
