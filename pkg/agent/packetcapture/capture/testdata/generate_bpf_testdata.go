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

//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// Pre-compiled regular expressions for parsing tcpdump -d output lines.
var (
	reLoadAbsolute = regexp.MustCompile(`^\((\d+)\)\s+(ldh|ldb|ld)\s+\[(\d+)\]$`)
	reJump         = regexp.MustCompile(`^\((\d+)\)\s+(jeq|jset)\s+#(0x[\da-fA-F]+)\s+jt\s+(\d+)\s+jf\s+(\d+)$`)
	reReturn       = regexp.MustCompile(`^\((\d+)\)\s+ret\s+#(\d+)$`)
	reLoadMemShift = regexp.MustCompile(`^\((\d+)\)\s+ldxb\s+4\*\(\[(\d+)\]&0xf\)$`)
	reLoadIndirect = regexp.MustCompile(`^\((\d+)\)\s+(ldh|ldb|ld)\s+\[x\s*\+\s*(\d+)\]$`)
	reALUAnd       = regexp.MustCompile(`^\((\d+)\)\s+and\s+#(0x[\da-fA-F]+)$`)
	reTax          = regexp.MustCompile(`^\((\d+)\)\s+tax$`)
)

func sizeFromOpcode(opcode string) int {
	switch opcode {
	case "ld":
		return 4
	case "ldh":
		return 2
	case "ldb":
		return 1
	default:
		return 0
	}
}

func parseLine(line string) (bpf.Instruction, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	if m := reLoadAbsolute.FindStringSubmatch(line); m != nil {
		off, _ := strconv.ParseUint(m[3], 10, 32)
		return bpf.LoadAbsolute{Off: uint32(off), Size: sizeFromOpcode(m[2])}, nil
	}
	if m := reJump.FindStringSubmatch(line); m != nil {
		idx, _ := strconv.ParseUint(m[1], 10, 32)
		val, _ := strconv.ParseUint(m[3][2:], 16, 32)
		jt, _ := strconv.ParseUint(m[4], 10, 32)
		jf, _ := strconv.ParseUint(m[5], 10, 32)
		cond := bpf.JumpEqual
		if m[2] == "jset" {
			cond = bpf.JumpBitsSet
		}
		return bpf.JumpIf{
			Cond:      cond,
			Val:       uint32(val),
			SkipTrue:  uint8(jt - idx - 1),
			SkipFalse: uint8(jf - idx - 1),
		}, nil
	}
	if m := reReturn.FindStringSubmatch(line); m != nil {
		val, _ := strconv.ParseUint(m[2], 10, 32)
		return bpf.RetConstant{Val: uint32(val)}, nil
	}
	if m := reLoadMemShift.FindStringSubmatch(line); m != nil {
		off, _ := strconv.ParseUint(m[2], 10, 32)
		return bpf.LoadMemShift{Off: uint32(off)}, nil
	}
	if m := reLoadIndirect.FindStringSubmatch(line); m != nil {
		off, _ := strconv.ParseUint(m[3], 10, 32)
		return bpf.LoadIndirect{Off: uint32(off), Size: sizeFromOpcode(m[2])}, nil
	}
	if m := reALUAnd.FindStringSubmatch(line); m != nil {
		val, _ := strconv.ParseUint(m[2][2:], 16, 32)
		return bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: uint32(val)}, nil
	}
	if reTax.MatchString(line) {
		return bpf.TAX{}, nil
	}
	return nil, fmt.Errorf("unsupported tcpdump instruction format: %q", line)
}

func parseTcpdumpOutput(output string) ([]bpf.Instruction, error) {
	var instructions []bpf.Instruction
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Warning:") {
			continue
		}
		inst, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("parsing tcpdump output: %w", err)
		}
		if inst != nil {
			instructions = append(instructions, inst)
		}
	}
	return instructions, nil
}

func extractFilterInputsFromInputsTest(filePath string) (map[string]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	reName := regexp.MustCompile(`^\s*Name:\s*"([^"]+)",\s*$`)
	reFilter := regexp.MustCompile(`^\s*TcpdumpFilter:\s*"([^"]+)",\s*$`)

	filters := make(map[string]string)
	var currentName string
	for _, line := range strings.Split(string(content), "\n") {
		if m := reName.FindStringSubmatch(line); m != nil {
			currentName = m[1]
			continue
		}
		if m := reFilter.FindStringSubmatch(line); m != nil && currentName != "" {
			filters[currentName] = m[1]
			currentName = ""
		}
	}

	if len(filters) == 0 {
		return nil, fmt.Errorf("no BPF test case filters found in %s", filePath)
	}
	return filters, nil
}

func main() {
	filterInputs, err := extractFilterInputsFromInputsTest("inputs_test.go")
	if err != nil {
		log.Fatalf("failed to load tcpdump filters from inputs_test.go: %v", err)
	}
	log.Println("Generating reference BPF instructions from BPFTestCases...")

	var b bytes.Buffer
	b.WriteString(`// Copyright 2026 Antrea Authors.
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

import "golang.org/x/net/bpf"

// generatedBPFTestCases contains the reference BPF arrays generated via tcpdump -d.
var generatedBPFTestCases = map[string][]bpf.RawInstruction{
`)

	names := make([]string, 0, len(filterInputs))
	for name := range filterInputs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		filter := filterInputs[name]
		log.Printf("Running tcpdump for: %s", name)
		cmd := exec.Command("tcpdump", "-d", filter)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("tcpdump failed for '%s': %v\nOutput:%s", filter, err, string(out))
		}

		insts, err := parseTcpdumpOutput(string(out))
		if err != nil {
			log.Fatalf("Failed to parse tcpdump output for '%s': %v", name, err)
		}

		rawInsts, err := bpf.Assemble(insts)
		if err != nil {
			log.Fatalf("Failed to assemble BPF for '%s': %v", name, err)
		}

		b.WriteString(fmt.Sprintf("\t%q: {\n", name))
		for _, raw := range rawInsts {
			b.WriteString(fmt.Sprintf("\t\t{Op: %d, Jt: %d, Jf: %d, K: %d},\n", raw.Op, raw.Jt, raw.Jf, raw.K))
		}
		b.WriteString("\t},\n")
	}

	b.WriteString("}\n")

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("Failed to format generated source: %v", err)
	}

	err = os.WriteFile("zz_generated_bpf_testdata_test.go", formatted, 0o644)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}

	log.Println("Successfully generated zz_generated_bpf_testdata_test.go!")
}
