//go:build ignore
// +build ignore

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

// These filters must match the entries in inputs_test.go.
var filterInputs = map[string]string{
	"ICMP protocol only":                                          "icmp",
	"UDP protocol only":                                           "ip proto 17",
	"TCP with dst port 80":                                        "ip proto 6 and dst port 80",
	"TCP with src+dst IP and src+dst port":                        "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80",
	"TCP with srcIP only and src+dst port":                        "ip proto 6 and src host 127.0.0.1 and src port 12345 and dst port 80",
	"UDP with dstIP only and src+dst port":                        "ip proto 17 and dst host 127.0.0.2 and src port 12345 and dst port 80",
	"UDP with src+dst IP and src+dst port":                        "ip proto 17 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80",
	"ICMP dst-unreachable with code 1":                            "ip proto 1 and src host 127.0.0.1 and dst host 127.0.0.2 and icmp[0]=3 and icmp[1]=1",
	"TCP with SYN flag and IPs":                                   "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and (tcp[tcpflags] & tcp-syn == tcp-syn)",
	"IPv6 TCP with DstPort 80":                                    "ip6 proto 6 and dst port 80",
	"ICMPv6 (IPv6 protocol only)":                                 "ip6 proto 58",
	"IPv6 TCP SrcPort+DstPort":                                    "ip6 proto 6 and src port 12345 and dst port 80",
	"IPv6 TCP with SrcIP+DstIP (no ports)":                        "ip6 proto 6 and src host fd00:10:244::1 and dst host fd00:10:244::2",
	"ICMPv6 with type and code":                                   "ip6 proto 58 and icmp6[0]=3 and icmp6[1]=1",
	"IPv4 TCP exact flags (SYN set, ACK cleared)":                 "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80 and (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)",
	"IPv4 TCP exact strict flags (SYN+ACK only) with IP and Port": "ip proto 6 and src host 1.2.3.4 and dst port 443 and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push|tcp-ack) == (tcp-syn|tcp-ack))",
	"IPv4 UDP with DstPort only":                                  "ip proto 17 and dst port 53",
	"ICMP with Type only":                                         "ip proto 1 and icmp[0]=8",
	"IPv4 TCP with RST flag":                                      "ip proto 6 and (tcp[tcpflags] & tcp-rst == tcp-rst)",
	"IPv4 IP only without transport":                              "ip proto 6 and src host 10.0.0.1 and dst host 10.0.0.2",
	"IPv6 UDP with SrcPort only":                                  "ip6 proto 17 and src port 12345",
	"IPv6 UDP full combo with optimized order":                    "ip6 and src host fd00:10:244::1 and dst host fd00:10:244::2 and proto 17 and src port 12345 and dst port 80",
	"IPv6 TCP with srcIP only and src+dst ports":                  "ip6 and src host fd00:10:244::1 and proto 6 and src port 12345 and dst port 80",
	"IPv6 TCP with dstIP only and src+dst ports":                  "ip6 and dst host fd00:10:244::2 and proto 6 and src port 12345 and dst port 80",
	"IPv6 UDP with srcIP only and src+dst ports":                  "ip6 and src host fd00:10:244::1 and proto 17 and src port 12345 and dst port 80",
	"IPv6 UDP with dstIP only and src+dst ports":                  "ip6 and dst host fd00:10:244::2 and proto 17 and src port 12345 and dst port 80",
	"IPv6 ICMPv6 type+code with srcIP only":                       "ip6 and src host fd00:10:244::1 and proto 58 and icmp6[0]=128 and icmp6[1]=1",
	"IPv6 ICMPv6 type+code with dstIP only":                       "ip6 and dst host fd00:10:244::2 and proto 58 and icmp6[0]=128 and icmp6[1]=1",
	"IPv6 TCP src+dst IP and src+dst ports DestinationToSource":   "ip6 and src host fd00:10:244::2 and dst host fd00:10:244::1 and proto 6 and src port 80 and dst port 12345",
	"IPv6 UDP src+dst IP and src+dst ports DestinationToSource":   "ip6 and src host fd00:10:244::2 and dst host fd00:10:244::1 and proto 17 and src port 80 and dst port 12345",
	"IPv4 TCP src+dst IP and src+dst ports DestinationToSource alt": "ip proto 6 and src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345",
	"IPv4 UDP src+dst IP and src+dst ports DestinationToSource alt": "ip proto 17 and src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345",
	"IPv4 ICMP time exceeded with code 0 unique":                    "ip proto 1 and src host 10.0.0.1 and dst host 10.0.0.2 and icmp[0]=11 and icmp[1]=0",
	"IPv6 ICMPv6 echo reply with src+dst IP unique":                 "ip6 and src host fd00:10:244::1 and dst host fd00:10:244::2 and proto 58 and icmp6[0]=129",
	"IPv6 numeric protocol 132 only unique":                         "ip6 proto 132",
}

func main() {
	log.Println("Generating reference BPF instructions using tcpdump offline...")

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

// Code generated by generate_bpf_testdata.go; DO NOT EDIT.
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
