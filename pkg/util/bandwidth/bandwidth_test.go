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

package bandwidth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestParseBandwidth(t *testing.T) {
	fakeBandwidth1, _ := resource.ParseQuantity("2M")
	fakeBandwidth2, _ := resource.ParseQuantity("2G")

	testcases := []struct {
		bandwidthString   string
		expectedScale     resource.Scale
		expectedBandwidth uint32
		expectedError     error
	}{
		{
			bandwidthString:   "",
			expectedScale:     Mega,
			expectedBandwidth: uint32(0),
			expectedError:     nil,
		},
		{
			bandwidthString:   "2M",
			expectedScale:     Mega,
			expectedBandwidth: uint32(fakeBandwidth1.ScaledValue(Mega)),
			expectedError:     nil,
		},
		{
			bandwidthString:   "2G",
			expectedScale:     Giga,
			expectedBandwidth: uint32(fakeBandwidth2.ScaledValue(Giga)),
			expectedError:     nil,
		},
		{
			bandwidthString:   "2T",
			expectedScale:     resource.Tera,
			expectedBandwidth: uint32(0),
			expectedError:     fmt.Errorf("resoruce is unreasonably large (> 1Tbit)"),
		},
		{
			bandwidthString:   "2A",
			expectedScale:     resource.Peta,
			expectedBandwidth: uint32(0),
			expectedError:     fmt.Errorf("quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'"),
		},
	}
	for _, tc := range testcases {
		parsedBandwidth, err := ParseBandwidth(tc.bandwidthString, tc.expectedScale)
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
		} else {
			require.Nil(t, err)
			assert.Equal(t, tc.expectedBandwidth, parsedBandwidth)
		}

	}
}
