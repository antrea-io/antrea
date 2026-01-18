// Copyright 2024 Antrea Authors.
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

package capture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

func TestParseTcpdumpOutput(t *testing.T) {
	tt := []struct {
		name     string
		input    string
		expected []bpf.Instruction
		wantErr  bool
	}{
		{
			name: "simple-ipv4-tcp",
			input: `(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 8
(002) ldb      [23]
(003) jeq      #0x6             jt 4    jf 8
(004) ld       [26]
(005) jeq      #0x7f000001      jt 6    jf 8
(006) ld       [30]
(007) jeq      #0x7f000002      jt 9    jf 8
(008) ret      #0
(009) ret      #262144`,
			expected: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: lengthHalf},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 6},
				bpf.LoadAbsolute{Off: 23, Size: lengthByte},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 4},
				bpf.LoadAbsolute{Off: 26, Size: lengthWord},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 2},
				bpf.LoadAbsolute{Off: 30, Size: lengthWord},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 0},
				bpf.RetConstant{Val: 262144},
			},
		},
		{
			name: "with-port-filter",
			input: `(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4    jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10   jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11   jf 9
(009) ldh      [x + 16]
(010) jeq      #0x50            jt 11   jf 12
(011) ret      #262144
(012) ret      #0`,
			expected: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: lengthHalf},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 23, Size: lengthByte},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 6},
				bpf.LoadAbsolute{Off: 20, Size: lengthHalf},
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4, SkipFalse: 0},
				bpf.LoadMemShift{Off: 14},
				bpf.LoadIndirect{Off: 14, Size: lengthHalf},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 2, SkipFalse: 0},
				bpf.LoadIndirect{Off: 16, Size: lengthHalf},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:     "empty-input",
			input:    "",
			expected: []bpf.Instruction{},
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result, err := ParseTcpdumpOutput(item.input)
			if item.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, item.expected, result)
		})
	}
}

func TestParseLine(t *testing.T) {
	tt := []struct {
		name     string
		line     string
		expected bpf.Instruction
		wantErr  bool
	}{
		{
			name:     "ldh-absolute",
			line:     "(000) ldh      [12]",
			expected: bpf.LoadAbsolute{Off: 12, Size: lengthHalf},
		},
		{
			name:     "ldb-absolute",
			line:     "(002) ldb      [23]",
			expected: bpf.LoadAbsolute{Off: 23, Size: lengthByte},
		},
		{
			name:     "ld-absolute",
			line:     "(004) ld       [26]",
			expected: bpf.LoadAbsolute{Off: 26, Size: lengthWord},
		},
		{
			name:     "ldxb-memshift",
			line:     "(006) ldxb     4*([14]&0xf)",
			expected: bpf.LoadMemShift{Off: 14},
		},
		{
			name:     "ldh-indirect",
			line:     "(007) ldh      [x + 14]",
			expected: bpf.LoadIndirect{Off: 14, Size: lengthHalf},
		},
		{
			name:     "jeq-hex",
			line:     "(001) jeq      #0x800           jt 2    jf 16",
			expected: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 14},
		},
		{
			name:     "jset",
			line:     "(009) jset     #0x1fff          jt 16   jf 10",
			expected: bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},
		},
		{
			name:     "ret-match",
			line:     "(015) ret      #262144",
			expected: bpf.RetConstant{Val: 262144},
		},
		{
			name:     "ret-drop",
			line:     "(016) ret      #0",
			expected: bpf.RetConstant{Val: 0},
		},
		{
			name:     "alu-and",
			line:     "(012) and      #0x2",
			expected: bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x2},
		},
		{
			name:    "invalid",
			line:    "garbage input",
			wantErr: true,
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result, err := parseLine(item.line)
			if item.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, item.expected, result)
		})
	}
}
