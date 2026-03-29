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
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
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
		off, err := strconv.ParseUint(m[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse offset %q: %v", m[3], err)
		}
		return bpf.LoadAbsolute{Off: uint32(off), Size: sizeFromOpcode(m[2])}, nil
	}
	if m := reJump.FindStringSubmatch(line); m != nil {
		idx, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse instruction index %q: %v", m[1], err)
		}
		val, err := strconv.ParseUint(m[3][2:], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jump value %q: %v", m[3], err)
		}
		jt, err := strconv.ParseUint(m[4], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jt offset %q: %v", m[4], err)
		}
		jf, err := strconv.ParseUint(m[5], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jf offset %q: %v", m[5], err)
		}
		if jt <= idx || jf <= idx {
			return nil, fmt.Errorf("invalid jump offsets: jt=%d, jf=%d must be > idx=%d", jt, jf, idx)
		}
		skipTrue := jt - idx - 1
		skipFalse := jf - idx - 1
		if skipTrue > 255 || skipFalse > 255 {
			return nil, fmt.Errorf("jump offsets exceed uint8 range: skipTrue=%d, skipFalse=%d", skipTrue, skipFalse)
		}
		cond := bpf.JumpEqual
		if m[2] == "jset" {
			cond = bpf.JumpBitsSet
		}
		return bpf.JumpIf{
			Cond:      cond,
			Val:       uint32(val),
			SkipTrue:  uint8(skipTrue),
			SkipFalse: uint8(skipFalse),
		}, nil
	}
	if m := reReturn.FindStringSubmatch(line); m != nil {
		val, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse return value %q: %v", m[2], err)
		}
		return bpf.RetConstant{Val: uint32(val)}, nil
	}
	if m := reLoadMemShift.FindStringSubmatch(line); m != nil {
		off, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse memory offset %q: %v", m[2], err)
		}
		return bpf.LoadMemShift{Off: uint32(off)}, nil
	}
	if m := reLoadIndirect.FindStringSubmatch(line); m != nil {
		off, err := strconv.ParseUint(m[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse indirect offset %q: %v", m[3], err)
		}
		return bpf.LoadIndirect{Off: uint32(off), Size: sizeFromOpcode(m[2])}, nil
	}
	if m := reALUAnd.FindStringSubmatch(line); m != nil {
		val, err := strconv.ParseUint(m[2][2:], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse and constant %q: %v", m[2], err)
		}
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
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filePath, err)
	}

	var casesLit *ast.CompositeLit
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if name.Name != "BPFTestCases" || i >= len(valueSpec.Values) {
					continue
				}
				if lit, ok := valueSpec.Values[i].(*ast.CompositeLit); ok {
					casesLit = lit
					break
				}
			}
			if casesLit != nil {
				break
			}
		}
		if casesLit != nil {
			break
		}
	}
	if casesLit == nil {
		return nil, fmt.Errorf("BPFTestCases declaration not found in %s", filePath)
	}

	readString := func(expr ast.Expr) (string, bool, error) {
		lit, ok := expr.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false, nil
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "", false, fmt.Errorf("invalid string literal %s: %w", lit.Value, err)
		}
		return value, true, nil
	}

	filters := make(map[string]string)
	for _, elt := range casesLit.Elts {
		testCaseLit, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}

		var (
			name   string
			filter string
		)

		for _, field := range testCaseLit.Elts {
			kv, ok := field.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}

			switch key.Name {
			case "Name":
				value, ok, err := readString(kv.Value)
				if err != nil {
					return nil, fmt.Errorf("extract Name at %s: %w", fset.Position(kv.Pos()), err)
				}
				if ok {
					name = value
				}
			case "TcpdumpFilter":
				value, ok, err := readString(kv.Value)
				if err != nil {
					return nil, fmt.Errorf("extract TcpdumpFilter at %s: %w", fset.Position(kv.Pos()), err)
				}
				if ok {
					filter = value
				}
			}
		}

		if name != "" && filter != "" {
			filters[name] = filter
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
