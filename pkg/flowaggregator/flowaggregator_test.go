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

package flowaggregator

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"

	ipfixtest "github.com/vmware-tanzu/antrea/pkg/ipfix/testing"
)

const (
	testTemplateID          = uint16(256)
	testExportInterval      = 60 * time.Second
	testObservationDomainID = 0xabcd
)

// TODO: We will add another test for sendDataRecord when we support adding multiple records to single set.
// Currently, we are supporting adding only one record from one flow key to the set.

func TestFlowAggregator_sendTemplateSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixtest.NewMockIPFIXSet(ctrl)

	fa := &flowAggregator{
		"",
		"",
		"tcp",
		nil,
		nil,
		testExportInterval,
		mockIPFIXExpProc,
		testTemplateID,
		mockIPFIXRegistry,
		ipfixtest.NewMockIPFIXSet(ctrl),
		"",
		nil,
		testObservationDomainID,
	}

	// Following consists of all elements that are in ianaInfoElements and antreaInfoElements (globals)
	// Only the element name is needed, other arguments have dummy values.
	elemList := make([]*ipfixentities.InfoElementWithValue, 0)
	for i, ie := range ianaInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].Element, nil)
	}
	for i, ie := range ianaReverseInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(ianaInfoElements)].Element, nil)
	}
	for i, ie := range antreaInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)].Element, nil)
	}
	for i, ie := range aggregatorElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)].Element, nil)
	}
	for i, ie := range antreaSourceStatsElementList {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)+len(aggregatorElements)].Element, nil)
	}

	for i, ie := range antreaDestinationStatsElementList {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)+len(aggregatorElements)+len(antreaSourceStatsElementList)].Element, nil)
	}
	var tempSet ipfixentities.Set
	mockTempSet.EXPECT().AddRecord(elemList, testTemplateID).Return(nil)
	mockTempSet.EXPECT().GetSet().Return(tempSet)

	// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
	// above elements: ianaInfoElements, ianaReverseInfoElements and antreaInfoElements.
	mockIPFIXExpProc.EXPECT().SendSet(tempSet).Return(0, nil)

	_, err := fa.sendTemplateSet(mockTempSet)
	assert.NoErrorf(t, err, "Error in sending template record: %v", err)
}
