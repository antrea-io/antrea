// Copyright 2026 Antrea Authors
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

// gen-bpf-objects turns the object file clang produces for an eBPF program into a Go source file, so that
// loading it at run time needs no ELF parsing and no BPF library: what it emits is the instructions, the map
// definitions and the list of instructions holding a map reference, which is all the loader has to know.
//
// The map definitions are read from the .hostdp_maps section, where the C file puts one plain structure per
// map, rather than from BTF. Reading BTF is what a general purpose loader has to do, and it is most of one;
// this only has to read a layout the same repository defines.
//
// The source file is hashed into the output so that a build can tell that the two have drifted apart without
// running clang, which is what pkg/agent/ebpf/objects_hash_test.go checks.
//
// Usage: gen-bpf-objects -obj host_datapath.o -src host_datapath.bpf.c -package ebpf -out objects_linux.go
package main

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// instructionSize is the size of an eBPF instruction. A wide instruction, which is the only one holding a map
// reference, takes two of those.
const instructionSize = 8

// mapSectionName is the section the C file puts its map definitions in, and mapDefSize is the size of one:
// five 32 bit fields, see struct hostdp_map_def.
const (
	mapSectionName = ".hostdp_maps"
	mapDefSize     = 20
)

// programSectionName is the section clang puts a SEC("tc") program in.
const programSectionName = "tc"

type mapDef struct {
	Name       string
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type mapReloc struct {
	// Instruction is the index, in the program, of the wide instruction whose immediate is the map.
	Instruction uint32
	MapIndex    uint32
}

type programDef struct {
	Name         string
	Instructions []byte
	Relocs       []mapReloc
}

func main() {
	objPath := flag.String("obj", "", "the object file clang produced")
	srcPath := flag.String("src", "", "the C source it was produced from, hashed into the output")
	pkg := flag.String("package", "", "the package of the generated file")
	outPath := flag.String("out", "", "the Go file to write")
	flag.Parse()
	if *objPath == "" || *srcPath == "" || *pkg == "" || *outPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*objPath, *srcPath, *pkg, *outPath); err != nil {
		fmt.Fprintf(os.Stderr, "gen-bpf-objects: %v\n", err)
		os.Exit(1)
	}
}

func run(objPath, srcPath, pkg, outPath string) error {
	src, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	f, err := elf.Open(objPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if f.Machine != elf.EM_BPF {
		return fmt.Errorf("%s is not a BPF object, its machine is %s", objPath, f.Machine)
	}
	// A program calling another one would need its callee appended and its call offsets rewritten. The C
	// file inlines everything instead, so refuse an object which stopped being that way rather than
	// loading a program with a dangling call.
	if text := f.Section(".text"); text != nil && text.Size != 0 {
		return fmt.Errorf(".text holds %d bytes: the programs must not call each other, inline the callee",
			text.Size)
	}
	symbols, err := f.Symbols()
	if err != nil {
		return fmt.Errorf("reading the symbols: %w", err)
	}

	maps, mapIndexByName, err := readMaps(f, symbols)
	if err != nil {
		return err
	}
	programs, err := readPrograms(f, symbols, mapIndexByName)
	if err != nil {
		return err
	}
	if len(programs) == 0 {
		return fmt.Errorf("no program found in section %q", programSectionName)
	}

	out, err := render(pkg, filepath.Base(srcPath), sha256.Sum256(src), maps, programs)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0644)
}

// readMaps reads the map definitions the C file laid out in its own section, in the order of their address so
// that the generated file does not change when the linker reorders the symbols.
func readMaps(f *elf.File, symbols []elf.Symbol) ([]mapDef, map[string]uint32, error) {
	section := f.Section(mapSectionName)
	if section == nil {
		return nil, nil, fmt.Errorf("section %q not found", mapSectionName)
	}
	data, err := section.Data()
	if err != nil {
		return nil, nil, err
	}
	sectionIndex := -1
	for i, s := range f.Sections {
		if s == section {
			sectionIndex = i
		}
	}
	var defined []elf.Symbol
	for _, sym := range symbols {
		if int(sym.Section) == sectionIndex && sym.Name != "" {
			defined = append(defined, sym)
		}
	}
	sort.Slice(defined, func(i, j int) bool { return defined[i].Value < defined[j].Value })

	maps := make([]mapDef, 0, len(defined))
	index := make(map[string]uint32, len(defined))
	for _, sym := range defined {
		if sym.Size != mapDefSize {
			return nil, nil, fmt.Errorf("map %q is %d bytes, expected %d: struct hostdp_map_def and "+
				"mapDefSize have drifted apart", sym.Name, sym.Size, mapDefSize)
		}
		if sym.Value+mapDefSize > uint64(len(data)) {
			return nil, nil, fmt.Errorf("map %q lies outside %s", sym.Name, mapSectionName)
		}
		b := data[sym.Value : sym.Value+mapDefSize]
		def := mapDef{
			Name:       sym.Name,
			Type:       binary.LittleEndian.Uint32(b[0:]),
			KeySize:    binary.LittleEndian.Uint32(b[4:]),
			ValueSize:  binary.LittleEndian.Uint32(b[8:]),
			MaxEntries: binary.LittleEndian.Uint32(b[12:]),
			Flags:      binary.LittleEndian.Uint32(b[16:]),
		}
		if def.Type == 0 || def.MaxEntries == 0 {
			return nil, nil, fmt.Errorf("map %q has type %d and %d entries, neither can be zero",
				def.Name, def.Type, def.MaxEntries)
		}
		index[def.Name] = uint32(len(maps))
		maps = append(maps, def)
	}
	if len(maps) == 0 {
		return nil, nil, fmt.Errorf("no map found in %s", mapSectionName)
	}
	return maps, index, nil
}

// readPrograms cuts the program section into one program per function symbol and collects, for each of them,
// the instructions holding a reference to a map.
func readPrograms(f *elf.File, symbols []elf.Symbol, mapIndexByName map[string]uint32) ([]programDef, error) {
	section := f.Section(programSectionName)
	if section == nil {
		return nil, fmt.Errorf("section %q not found", programSectionName)
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	sectionIndex := -1
	for i, s := range f.Sections {
		if s == section {
			sectionIndex = i
		}
	}
	relocs, err := readRelocations(f, sectionIndex, symbols)
	if err != nil {
		return nil, err
	}

	var functions []elf.Symbol
	for _, sym := range symbols {
		if int(sym.Section) == sectionIndex && elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Size != 0 {
			functions = append(functions, sym)
		}
	}
	sort.Slice(functions, func(i, j int) bool { return functions[i].Value < functions[j].Value })

	programs := make([]programDef, 0, len(functions))
	for _, sym := range functions {
		start, end := sym.Value, sym.Value+sym.Size
		if end > uint64(len(data)) {
			return nil, fmt.Errorf("program %q lies outside %s", sym.Name, programSectionName)
		}
		if sym.Size%instructionSize != 0 {
			return nil, fmt.Errorf("program %q is %d bytes, not a whole number of instructions",
				sym.Name, sym.Size)
		}
		program := programDef{Name: sym.Name, Instructions: data[start:end]}
		for offset, target := range relocs {
			if offset < start || offset >= end {
				continue
			}
			mapIndex, ok := mapIndexByName[target]
			if !ok {
				return nil, fmt.Errorf("program %q references %q, which is not a map", sym.Name, target)
			}
			if offset%instructionSize != 0 {
				return nil, fmt.Errorf("program %q has a relocation at offset %d, which is not an "+
					"instruction boundary", sym.Name, offset)
			}
			program.Relocs = append(program.Relocs, mapReloc{
				Instruction: uint32((offset - start) / instructionSize),
				MapIndex:    mapIndex,
			})
		}
		sort.Slice(program.Relocs, func(i, j int) bool {
			return program.Relocs[i].Instruction < program.Relocs[j].Instruction
		})
		programs = append(programs, program)
	}
	return programs, nil
}

// readRelocations returns the symbol name referenced at each relocated offset of a section.
func readRelocations(f *elf.File, sectionIndex int, symbols []elf.Symbol) (map[uint64]string, error) {
	relocs := make(map[uint64]string)
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL || int(s.Info) != sectionIndex {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, err
		}
		if len(data)%16 != 0 {
			return nil, fmt.Errorf("%s is %d bytes, not a whole number of relocations", s.Name, len(data))
		}
		for i := 0; i+16 <= len(data); i += 16 {
			offset := binary.LittleEndian.Uint64(data[i:])
			info := binary.LittleEndian.Uint64(data[i+8:])
			// The symbol index is the upper half of the info field, and the symbol table is one
			// based, its first entry being the reserved one debug/elf leaves out.
			symIndex := int(info>>32) - 1
			if symIndex < 0 || symIndex >= len(symbols) {
				return nil, fmt.Errorf("%s references symbol %d, which does not exist", s.Name, symIndex+1)
			}
			relocs[offset] = symbols[symIndex].Name
		}
	}
	return relocs, nil
}

func render(pkg, srcName string, sum [32]byte, maps []mapDef, programs []programDef) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, `// Copyright 2026 Antrea Authors
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

// Code generated by hack/gen-bpf-objects from %s. DO NOT EDIT.

package %s

// bpfSourceSHA256 is the hash of %s when this file was generated. objects_hash_test.go compares it with the
// hash of the file in the tree, so that changing the C without regenerating this one fails a build rather
// than silently loading the instructions of an older version.
const bpfSourceSHA256 = %q

var bpfMaps = []mapDef{
`, srcName, pkg, srcName, hex.EncodeToString(sum[:]))

	for _, m := range maps {
		fmt.Fprintf(&b, "\t{name: %q, mapType: %d, keySize: %d, valueSize: %d, maxEntries: %d, flags: %d},\n",
			m.Name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
	}
	b.WriteString("}\n\nvar bpfPrograms = []programDef{\n")
	for _, p := range programs {
		fmt.Fprintf(&b, "\t{\n\t\tname: %q,\n\t\trelocs: []mapReloc{", p.Name)
		for i, r := range p.Relocs {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "{instruction: %d, mapIndex: %d}", r.Instruction, r.MapIndex)
		}
		fmt.Fprintf(&b, "},\n\t\t// %d instructions\n\t\tinstructions: %s,\n\t},\n",
			len(p.Instructions)/instructionSize, quoteBytes(p.Instructions))
	}
	b.WriteString("}\n")
	return format.Source([]byte(b.String()))
}

// quoteBytes renders the instructions as a Go string, which the compiler stores as is, rather than as a byte
// slice literal, which it would build one element at a time.
func quoteBytes(data []byte) string {
	var b strings.Builder
	b.WriteString(`"`)
	for i, c := range data {
		if i > 0 && i%16 == 0 {
			b.WriteString("\" +\n\t\t\t\"")
		}
		fmt.Fprintf(&b, "\\x%02x", c)
	}
	b.WriteString(`"`)
	return b.String()
}
