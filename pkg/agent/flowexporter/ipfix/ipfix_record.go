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
	"bytes"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
)

var _ IPFIXRecord = new(ipfixDataRecord)
var _ IPFIXRecord = new(ipfixTemplateRecord)

type IPFIXRecord interface {
	GetRecord() ipfixentities.Record
	PrepareRecord() (uint16, error)
	AddInfoElement(element *ipfixentities.InfoElement, val interface{}) (uint16, error)
	GetBuffer() *bytes.Buffer
	GetTemplateElements() []*ipfixentities.InfoElement
	GetFieldCount() uint16
}

type ipfixDataRecord struct {
	dataRecord ipfixentities.Record
}

type ipfixTemplateRecord struct {
	templateRecord ipfixentities.Record
}

func NewIPFIXDataRecord(tempID uint16) *ipfixDataRecord {
	dr := ipfixentities.NewDataRecord(tempID)
	return &ipfixDataRecord{dataRecord: dr}
}
func NewIPFIXTemplateRecord(elementCount uint16, tempID uint16) *ipfixTemplateRecord {
	tr := ipfixentities.NewTemplateRecord(elementCount, tempID)
	return &ipfixTemplateRecord{templateRecord: tr}
}

func (dr *ipfixDataRecord) GetRecord() ipfixentities.Record {
	return dr.dataRecord
}

func (dr *ipfixDataRecord) PrepareRecord() (uint16, error) {
	addedBytes, err := dr.dataRecord.PrepareRecord()
	return addedBytes, err
}

func (dr *ipfixDataRecord) AddInfoElement(element *ipfixentities.InfoElement, val interface{}) (uint16, error) {
	addedBytes, err := dr.dataRecord.AddInfoElement(element, val)
	return addedBytes, err
}

func (dr *ipfixDataRecord) GetBuffer() *bytes.Buffer {
	return dr.dataRecord.GetBuffer()
}

func (dr *ipfixDataRecord) GetFieldCount() uint16 {
	return dr.dataRecord.GetFieldCount()
}

func (dr *ipfixDataRecord) GetTemplateElements() []*ipfixentities.InfoElement {
	return nil
}

func (tr *ipfixTemplateRecord) GetRecord() ipfixentities.Record {
	return tr.templateRecord
}

func (tr *ipfixTemplateRecord) PrepareRecord() (uint16, error) {
	addedBytes, err := tr.templateRecord.PrepareRecord()
	return addedBytes, err
}

func (tr *ipfixTemplateRecord) AddInfoElement(element *ipfixentities.InfoElement, val interface{}) (uint16, error) {
	addedBytes, err := tr.templateRecord.AddInfoElement(element, val)
	return addedBytes, err
}

func (tr *ipfixTemplateRecord) GetBuffer() *bytes.Buffer {
	return tr.templateRecord.GetBuffer()
}

func (tr *ipfixTemplateRecord) GetFieldCount() uint16 {
	return tr.templateRecord.GetFieldCount()
}

func (tr *ipfixTemplateRecord) GetTemplateElements() []*ipfixentities.InfoElement {
	return tr.templateRecord.GetTemplateElements()
}
