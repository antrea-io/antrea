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

package ipset

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type SetType string

const (
	// The hash:net set type uses a hash to store different sized IP network addresses.
	// The lookup time grows linearly with the number of the different prefix values added to the set.
	HashNet SetType = "hash:net"
	HashIP  SetType = "hash:ip"
)

// memberPattern is used to match the members part of ipset list result.
var memberPattern = regexp.MustCompile("(?m)^(.*\n)*Members:\n")

// CreateIPSet creates a new set, it will ignore error when the set already exists.
func CreateIPSet(name string, setType SetType, isIPv6 bool) error {
	var cmd *exec.Cmd
	if isIPv6 {
		cmd = exec.Command("ipset", "create", name, string(setType), "family", "inet6", "-exist")
	} else {
		cmd = exec.Command("ipset", "create", name, string(setType), "-exist")
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error creating ipset %s: %v", name, err)
	}
	return nil
}

// AddEntry adds a new entry to the set, it will ignore error when the entry already exists.
func AddEntry(name string, entry string) error {
	cmd := exec.Command("ipset", "add", name, entry, "-exist")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error adding entry %s to ipset %s: %v", entry, name, err)
	}
	return nil
}

// DelEntry deletes the entry from the set, it will ignore error when the entry doesn't exist.
func DelEntry(name string, entry string) error {
	cmd := exec.Command("ipset", "del", name, entry, "-exist")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error deleting entry %s from ipset %s: %v", entry, name, err)
	}
	return nil
}

// ListEntries lists all the entries of the set.
func ListEntries(name string) ([]string, error) {
	cmd := exec.Command("ipset", "list", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error listing ipset %s: %v", name, err)
	}
	memberStr := memberPattern.ReplaceAllString(string(output), "")
	lines := strings.Split(memberStr, "\n")
	entries := make([]string, 0, len(lines))
	for i := range lines {
		if len(lines[i]) > 0 {
			entries = append(entries, lines[i])
		}
	}
	return entries, nil
}
