// Copyright 2021 Antrea Authors
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
	"bytes"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
)

var _ IPFIXRecord = new(ipfixRecord)

// IPFIXRecord interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXRecord interface {
	PrepareRecord() (uint16, error)
	AddInfoElement(element *ipfixentities.InfoElementWithValue, isDecoding bool) (uint16, error)
	GetBuffer() *bytes.Buffer
	GetTemplateID() uint16
	GetFieldCount() uint16
	GetOrderedElementList() []*ipfixentities.InfoElementWithValue
	GetInfoElementWithValue(name string) (*ipfixentities.InfoElementWithValue, bool)
	GetMinDataRecordLen() uint16
}

type ipfixRecord struct {
	record ipfixentities.Record
}

func NewDataRecord(id uint16) *ipfixRecord {
	return &ipfixRecord{record: ipfixentities.NewDataRecord(id)}
}

func (r *ipfixRecord) PrepareRecord() (uint16, error) {
	return r.record.PrepareRecord()
}

func (r *ipfixRecord) AddInfoElement(element *ipfixentities.InfoElementWithValue, isDecoding bool) (uint16, error) {
	return r.record.AddInfoElement(element, isDecoding)
}

func (r *ipfixRecord) GetBuffer() *bytes.Buffer {
	return r.record.GetBuffer()
}

func (r *ipfixRecord) GetTemplateID() uint16 {
	return r.record.GetTemplateID()
}

func (r *ipfixRecord) GetFieldCount() uint16 {
	return r.record.GetFieldCount()
}

func (r *ipfixRecord) GetOrderedElementList() []*ipfixentities.InfoElementWithValue {
	return r.record.GetOrderedElementList()
}

func (r *ipfixRecord) GetInfoElementWithValue(name string) (*ipfixentities.InfoElementWithValue, bool) {
	return r.record.GetInfoElementWithValue(name)
}

func (r *ipfixRecord) GetMinDataRecordLen() uint16 {
	return r.record.GetMinDataRecordLen()
}
