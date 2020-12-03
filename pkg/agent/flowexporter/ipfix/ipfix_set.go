// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipfix

import (
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
)

var _ IPFIXSet = new(ipfixSet)

// IPFIXSet interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXSet interface {
	AddRecord(elements []*ipfixentities.InfoElementWithValue, templateID uint16) error
	GetSet() ipfixentities.Set
}

type ipfixSet struct {
	set ipfixentities.Set
}

func NewSet(setType ipfixentities.ContentType, templateID uint16, isDecoding bool) *ipfixSet {
	s := ipfixentities.NewSet(setType, templateID, isDecoding)
	return &ipfixSet{set: s}
}

func (s *ipfixSet) AddRecord(elements []*ipfixentities.InfoElementWithValue, templateID uint16) error {
	return s.set.AddRecord(elements, templateID)
}

func (s *ipfixSet) GetSet() ipfixentities.Set {
	return s.set
}
