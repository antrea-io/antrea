package ipfix

import (
	"bytes"
	ipfixentities "github.com/srikartati/go-ipfixlib/pkg/entities"
)

var _ IPFIXRecord = new(ipfixDataRecord)
var _ IPFIXRecord = new(ipfixTemplateRecord)

type IPFIXRecord interface {
	GetRecord() ipfixentities.Record
	PrepareRecord() (uint16, error)
	AddInfoElement(element *ipfixentities.InfoElement, val interface{}) (uint16, error)
	GetBuffer() *bytes.Buffer
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
