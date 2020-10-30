// +build !windows

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

package rules

import (
	nplutils "github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
)

type PodPortRules interface {
	Init() bool
	AddRule(port int, podip string) bool
	DeleteRule(port int, podip string) bool
	SyncState(podPort map[int]string) bool
	GetAllRules(podPort map[int]string) bool
	DeleteAllRules() bool
}

func Initrules(args ...nplutils.NPLRuleImplementation) PodPortRules {
	var ruletype nplutils.NPLRuleImplementation
	if len(args) == 0 {
		// By default use iptable
		ruletype = nplutils.NPLRuleImplementationIptable
	} else {
		ruletype = args[0]
	}
	switch ruletype {
	case nplutils.NPLRuleImplementationIptable:
		return NewIPTableRules()
	}
	return nil
}
