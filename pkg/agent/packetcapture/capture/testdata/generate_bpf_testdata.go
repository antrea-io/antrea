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
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// parseTcpdumpRawOutput parses the output of `tcpdump -ddd` which prints raw BPF
// numeric instructions. The first line is the instruction count, followed by
// one line per instruction in the format: "opcode jt jf k".
func parseTcpdumpRawOutput(output string) ([]bpf.RawInstruction, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("empty tcpdump -ddd output")
	}
	count, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse instruction count %q: %w", lines[0], err)
	}
	if len(lines)-1 != count {
		return nil, fmt.Errorf("expected %d instructions but got %d lines", count, len(lines)-1)
	}
	instructions := make([]bpf.RawInstruction, 0, count)
	for i := 1; i <= count; i++ {
		fields := strings.Fields(strings.TrimSpace(lines[i]))
		if len(fields) != 4 {
			return nil, fmt.Errorf("line %d: expected 4 fields, got %d: %q", i, len(fields), lines[i])
		}
		op, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid opcode %q: %w", i, fields[0], err)
		}
		jt, err := strconv.ParseUint(fields[1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid jt %q: %w", i, fields[1], err)
		}
		jf, err := strconv.ParseUint(fields[2], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid jf %q: %w", i, fields[2], err)
		}
		k, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid k %q: %w", i, fields[3], err)
		}
		instructions = append(instructions, bpf.RawInstruction{
			Op: uint16(op),
			Jt: uint8(jt),
			Jf: uint8(jf),
			K:  uint32(k),
		})
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

// generatedBPFTestCases contains the reference BPF arrays generated via tcpdump -ddd.
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
		cmd := exec.Command("tcpdump", "-ddd", filter)
		out, err := cmd.Output()
		if err != nil {
			log.Fatalf("tcpdump failed for '%s': %v", filter, err)
		}

		rawInsts, err := parseTcpdumpRawOutput(string(out))
		if err != nil {
			log.Fatalf("Failed to parse tcpdump -ddd output for '%s': %v", name, err)
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
