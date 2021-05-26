// Copyright 2021 Antrea Authors
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

package openflow

import (
	"fmt"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"
	"github.com/contiv/ofnet/ofctrl"
)

type ofMeter struct {
	ofctrl *ofctrl.Meter
	bridge *OFBridge
}

func (m *ofMeter) Reset() {
	m.ofctrl.Switch = m.bridge.ofSwitch
}

func (m *ofMeter) Add() error {
	return m.ofctrl.Install()
}

func (m *ofMeter) Modify() error {
	return m.ofctrl.Install()
}

func (m *ofMeter) Delete() error {
	return m.ofctrl.Delete()
}

func (m *ofMeter) Type() EntryType {
	return MeterEntry
}

func (m *ofMeter) KeyString() string {
	return fmt.Sprintf("meter_id:%d", m.ofctrl.ID)
}

func (m *ofMeter) GetBundleMessage(entryOper OFOperation) (ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow13.OFPMC_ADD
	case ModifyMessage:
		operation = openflow13.OFPMC_MODIFY
	case DeleteMessage:
		operation = openflow13.OFPMC_DELETE
	}
	message := m.ofctrl.GetBundleMessage(operation)
	return message, nil
}

func (m *ofMeter) ResetMeterBands() Meter {
	m.ofctrl.MeterBands = nil
	return m
}

func (m *ofMeter) MeterBand() MeterBandBuilder {
	return &meterBandBuilder{
		meter:           m,
		meterBandHeader: openflow13.NewMeterBandHeader(),
		prevLevel:       0,
		experimenter:    0,
	}
}

type meterBandBuilder struct {
	meter           *ofMeter
	meterBandHeader *openflow13.MeterBandHeader
	prevLevel       uint8
	experimenter    uint32
}

func (m *meterBandBuilder) MeterType(meterType ofctrl.MeterType) MeterBandBuilder {
	m.meterBandHeader.Type = uint16(meterType)
	return m
}

func (m *meterBandBuilder) Rate(rate uint32) MeterBandBuilder {
	m.meterBandHeader.Rate = rate
	return m
}

func (m *meterBandBuilder) Burst(burst uint32) MeterBandBuilder {
	m.meterBandHeader.BurstSize = burst
	return m
}

func (m *meterBandBuilder) PrecLevel(precLevel uint8) MeterBandBuilder {
	m.prevLevel = precLevel
	return m
}

func (m *meterBandBuilder) Experimenter(experimenter uint32) MeterBandBuilder {
	m.experimenter = experimenter
	return m
}

func (m *meterBandBuilder) Done() Meter {
	var mb util.Message
	switch m.meterBandHeader.Type {
	case uint16(ofctrl.MeterDrop):
		mbDrop := new(openflow13.MeterBandDrop)
		mbDrop.MeterBandHeader = *m.meterBandHeader
		mb = mbDrop
	case uint16(ofctrl.MeterDSCPRemark):
		mbDscp := new(openflow13.MeterBandDSCP)
		mbDscp.MeterBandHeader = *m.meterBandHeader
		mbDscp.PrecLevel = m.prevLevel
		mb = mbDscp
	case uint16(ofctrl.MeterExperimenter):
		mbExp := new(openflow13.MeterBandExperimenter)
		mbExp.MeterBandHeader = *m.meterBandHeader
		mbExp.Experimenter = m.experimenter
	}
	m.meter.ofctrl.AddMeterBand(&mb)
	return m.meter
}
