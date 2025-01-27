// Copyright 2025 Antrea Authors
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

package flowaggregator

import (
	"fmt"
	"net"

	"github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/klog/v2"
)

// preprocessor is in charge of processing messages received from the IPFIX collector, prior to
// proxying them to another collector of handing them over to the aggregation process. At the
// moment, its only task is to ensure that all records have the expected fields. If a record has
// extra fields, they will be discarded. If some fields are missing, they will be "appended" to the
// record with a "zero" value. For example, we will use 0 for integral types, "" for strings,
// 0.0.0.0 for IPv4 address, etc. Note that we are able to keep the implementation simple by
// assuming that a record either has missing fields or extra fields (not a combination of both), and
// that such fields are always at the tail of the field list. This assumption is based on
// implementation knowledge of the FlowExporter and the FlowAggregator.
type preprocessor struct {
	inCh  <-chan *entities.Message
	outCh chan<- *entities.Message

	expectedElementsV4 int
	expectedElementsV6 int

	defaultElementsWithValueV4 []entities.InfoElementWithValue
	defaultElementsWithValueV6 []entities.InfoElementWithValue
}

func makeDefaultElementWithValue(ie *entities.InfoElement) (entities.InfoElementWithValue, error) {
	switch ie.DataType {
	case entities.OctetArray:
		var val []byte
		if ie.Len < entities.VariableLength {
			val = make([]byte, ie.Len)
		}
		return entities.NewOctetArrayInfoElement(ie, val), nil
	case entities.Unsigned8:
		return entities.NewUnsigned8InfoElement(ie, 0), nil
	case entities.Unsigned16:
		return entities.NewUnsigned16InfoElement(ie, 0), nil
	case entities.Unsigned32:
		return entities.NewUnsigned32InfoElement(ie, 0), nil
	case entities.Unsigned64:
		return entities.NewUnsigned64InfoElement(ie, 0), nil
	case entities.Signed8:
		return entities.NewSigned8InfoElement(ie, 0), nil
	case entities.Signed16:
		return entities.NewSigned16InfoElement(ie, 0), nil
	case entities.Signed32:
		return entities.NewSigned32InfoElement(ie, 0), nil
	case entities.Signed64:
		return entities.NewSigned64InfoElement(ie, 0), nil
	case entities.Float32:
		return entities.NewFloat32InfoElement(ie, 0), nil
	case entities.Float64:
		return entities.NewFloat64InfoElement(ie, 0), nil
	case entities.Boolean:
		return entities.NewBoolInfoElement(ie, false), nil
	case entities.DateTimeSeconds:
		return entities.NewDateTimeSecondsInfoElement(ie, 0), nil
	case entities.DateTimeMilliseconds:
		return entities.NewDateTimeMillisecondsInfoElement(ie, 0), nil
	case entities.MacAddress:
		return entities.NewMacAddressInfoElement(ie, make([]byte, 6)), nil
	case entities.Ipv4Address:
		return entities.NewIPAddressInfoElement(ie, net.IPv4zero), nil
	case entities.Ipv6Address:
		return entities.NewIPAddressInfoElement(ie, net.IPv6zero), nil
	case entities.String:
		return entities.NewStringInfoElement(ie, ""), nil
	default:
		return nil, fmt.Errorf("unexpected Information Element data type: %d", ie.DataType)
	}
}

func makeDefaultElementsWithValue(infoElements []*entities.InfoElement) ([]entities.InfoElementWithValue, error) {
	elementsWithValue := make([]entities.InfoElementWithValue, len(infoElements))
	for idx := range infoElements {
		var err error
		if elementsWithValue[idx], err = makeDefaultElementWithValue(infoElements[idx]); err != nil {
			return nil, err
		}
	}
	return elementsWithValue, nil
}

func newPreprocessor(infoElementsV4, infoElementsV6 []*entities.InfoElement, inCh <-chan *entities.Message, outCh chan<- *entities.Message) (*preprocessor, error) {
	defaultElementsWithValueV4, err := makeDefaultElementsWithValue(infoElementsV4)
	if err != nil {
		return nil, fmt.Errorf("error when generating default values for IPv4 Information Elements expected from exporter: %w", err)
	}
	defaultElementsWithValueV6, err := makeDefaultElementsWithValue(infoElementsV6)
	if err != nil {
		return nil, fmt.Errorf("error when generating default values for IPv6 Information Elements expected from exporter: %w", err)
	}
	return &preprocessor{
		inCh:                       inCh,
		outCh:                      outCh,
		expectedElementsV4:         len(infoElementsV4),
		expectedElementsV6:         len(infoElementsV6),
		defaultElementsWithValueV4: defaultElementsWithValueV4,
		defaultElementsWithValueV6: defaultElementsWithValueV6,
	}, nil
}

func (p *preprocessor) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case msg, ok := <-p.inCh:
			if !ok {
				return
			}
			p.processMsg(msg)
		}
	}
}

func isRecordIPv4(record entities.Record) bool {
	_, _, exist := record.GetInfoElementWithValue("sourceIPv4Address")
	return exist
}

func (p *preprocessor) processMsg(msg *entities.Message) {
	set := msg.GetSet()
	if set.GetSetType() != entities.Data {
		return
	}
	records := set.GetRecords()
	if len(records) == 0 {
		return
	}
	// All the records in the data set must match a given template, so we only need to look at
	// the first one to decide how to proceed.
	firstRecord := records[0]
	elementList := firstRecord.GetOrderedElementList()
	numElements := len(elementList)
	isIPv4 := isRecordIPv4(firstRecord)
	expectedElements := p.expectedElementsV4
	if !isIPv4 {
		expectedElements = p.expectedElementsV6
	}
	// Fast path: everything matches so we can just forward the message as is.
	if numElements == expectedElements {
		p.outCh <- msg
		return
	}
	newSet := entities.NewSet(true)
	// Set templateID to 0: the set records will not match the template any more.
	if err := newSet.PrepareSet(entities.Data, 0); err != nil {
		klog.ErrorS(err, "Failed to prepare modified set")
		return
	}
	for _, record := range records {
		elementList := record.GetOrderedElementList()
		if numElements > expectedElements {
			if klog.V(5).Enabled() {
				klog.InfoS("Record received from exporter includes unexpected elements, truncating", "expectedElements", expectedElements, "receivedElements", numElements)
			}
			// Creating a new Record seems like the best option here. By using
			// AddRecordV2, we should minimize the number of allocations required.
			newSet.AddRecordV2(elementList[:expectedElements], 0)
		} else {
			if klog.V(5).Enabled() {
				klog.InfoS("Record received from exporter is missing information elements, adding fields with zero values", "expectedElements", expectedElements, "receivedElements", numElements)
			}
			if isIPv4 {
				elementList = append(elementList, p.defaultElementsWithValueV4[numElements:]...)
			} else {
				elementList = append(elementList, p.defaultElementsWithValueV6[numElements:]...)
			}
			newSet.AddRecordV2(elementList, 0)
		}
	}
	// This will overwrite the existing set with the new one.
	// Note that the message length will no longer be correct, but this should not matter.
	msg.AddSet(newSet)
	p.outCh <- msg
}
