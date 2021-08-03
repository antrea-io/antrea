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

package openflow

import (
	"fmt"
	"testing"

	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/require"
)

func TestMatchCTLabelRange(t *testing.T) {
	for _, tc := range []struct {
		rng                               Range
		expectedLowMask, expectedHighMask uint64
	}{
		{rng: Range{0, 0}, expectedLowMask: 0x1, expectedHighMask: 0x0},
		{rng: Range{1, 1}, expectedLowMask: 0b10, expectedHighMask: 0x0},
		{rng: Range{127, 127}, expectedLowMask: 0x0, expectedHighMask: 0x8000_0000_0000_0000},
		{rng: Range{126, 127}, expectedLowMask: 0x0, expectedHighMask: 0xc000_0000_0000_0000},
		{rng: Range{0, 127}, expectedLowMask: 0xffff_ffff_ffff_ffff, expectedHighMask: 0xffff_ffff_ffff_ffff},
		{rng: Range{0, 64}, expectedLowMask: 0xffff_ffff_ffff_ffff, expectedHighMask: 0x1},
		{rng: Range{0, 63}, expectedLowMask: 0xffff_ffff_ffff_ffff, expectedHighMask: 0x0},
		{rng: Range{64, 127}, expectedLowMask: 0x0, expectedHighMask: 0xffff_ffff_ffff_ffff},
	} {
		match := new(ofctrl.FlowMatch)
		ctLabelRange(0, 0, tc.rng, match)
		require.Equal(t, tc.expectedHighMask, match.CtLabelHiMask, fmt.Sprintf("Expected high mask is equal, test case: %+v", tc))
		require.Equal(t, tc.expectedLowMask, match.CtLabelLoMask, fmt.Sprintf("Expected low mask is equal, test case: %+v", tc))
	}
}
