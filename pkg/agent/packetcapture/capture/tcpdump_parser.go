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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// instructionParser defines how to match and parse a single tcpdump instruction line.
type instructionParser struct {
	pattern *regexp.Regexp
	parse   func(matches []string) (bpf.Instruction, error)
}

var instructionParsers = []instructionParser{
	// LoadAbsolute: ld/ldh/ldb [offset]
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+(ld[bhw]?)\s+\[(\d+)\]$`),
		parse: func(m []string) (bpf.Instruction, error) {
			off, _ := strconv.ParseUint(m[3], 10, 32)
			return bpf.LoadAbsolute{Off: uint32(off), Size: loadSize(m[2])}, nil
		},
	},
	// LoadMemShift: ldxb 4*([offset]&0xf)
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+ldxb\s+4\*\(\[(\d+)\]\&0xf\)$`),
		parse: func(m []string) (bpf.Instruction, error) {
			off, _ := strconv.ParseUint(m[2], 10, 32)
			return bpf.LoadMemShift{Off: uint32(off)}, nil
		},
	},
	// LoadIndirect: ld/ldh/ldb [x + offset]
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+(ld[bhw]?)\s+\[x\s*\+\s*(\d+)\]$`),
		parse: func(m []string) (bpf.Instruction, error) {
			off, _ := strconv.ParseUint(m[3], 10, 32)
			return bpf.LoadIndirect{Off: uint32(off), Size: loadSize(m[2])}, nil
		},
	},
	// JumpIf Equal: jeq #val jt N jf M
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+jeq\s+#(0x[0-9a-fA-F]+|\d+)\s+jt\s+(\d+)\s+jf\s+(\d+)$`),
		parse: func(m []string) (bpf.Instruction, error) {
			idx, _ := strconv.ParseUint(m[1], 10, 32)
			jt, _ := strconv.ParseUint(m[3], 10, 32)
			jf, _ := strconv.ParseUint(m[4], 10, 32)
			return bpf.JumpIf{
				Cond:      bpf.JumpEqual,
				Val:       parseUint32(m[2]),
				SkipTrue:  uint8(jt - idx - 1),
				SkipFalse: uint8(jf - idx - 1),
			}, nil
		},
	},
	// JumpIf BitsSet: jset #val jt N jf M
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+jset\s+#(0x[0-9a-fA-F]+|\d+)\s+jt\s+(\d+)\s+jf\s+(\d+)$`),
		parse: func(m []string) (bpf.Instruction, error) {
			idx, _ := strconv.ParseUint(m[1], 10, 32)
			jt, _ := strconv.ParseUint(m[3], 10, 32)
			jf, _ := strconv.ParseUint(m[4], 10, 32)
			return bpf.JumpIf{
				Cond:      bpf.JumpBitsSet,
				Val:       parseUint32(m[2]),
				SkipTrue:  uint8(jt - idx - 1),
				SkipFalse: uint8(jf - idx - 1),
			}, nil
		},
	},
	// RetConstant: ret #val
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+ret\s+#(\d+)$`),
		parse: func(m []string) (bpf.Instruction, error) {
			val, _ := strconv.ParseUint(m[2], 10, 32)
			return bpf.RetConstant{Val: uint32(val)}, nil
		},
	},
	// ALUOpConstant And: and #val
	{
		pattern: regexp.MustCompile(`^\((\d+)\)\s+and\s+#(0x[0-9a-fA-F]+|\d+)$`),
		parse: func(m []string) (bpf.Instruction, error) {
			return bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: parseUint32(m[2])}, nil
		},
	},
}

// ParseTcpdumpOutput parses tcpdump -d output into BPF instructions.
func ParseTcpdumpOutput(output string) ([]bpf.Instruction, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	instructions := make([]bpf.Instruction, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		inst, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		instructions = append(instructions, inst)
	}
	return instructions, nil
}

func parseLine(line string) (bpf.Instruction, error) {
	for _, p := range instructionParsers {
		if matches := p.pattern.FindStringSubmatch(line); matches != nil {
			return p.parse(matches)
		}
	}
	return nil, fmt.Errorf("unrecognized BPF instruction: %s", line)
}

func loadSize(op string) int {
	switch op {
	case "ldb":
		return lengthByte
	case "ldh":
		return lengthHalf
	default:
		return lengthWord
	}
}

func parseUint32(s string) uint32 {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, _ := strconv.ParseUint(s[2:], 16, 32)
		return uint32(val)
	}
	val, _ := strconv.ParseUint(s, 10, 32)
	return uint32(val)
}
