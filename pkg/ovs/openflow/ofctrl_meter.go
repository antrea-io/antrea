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
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
)

type ofMeter struct {
	ofctrl *ofctrl.Meter
	bridge *OFBridge
}

func (m *ofMeter) Reset() {
	m.ofctrl.Switch = m.bridge.ofSwitch
}

// Note: use OFSwitch to directly send MeterModification message rather than bundle message is because the
// current ofnet implementation for OpenFlow bundle does not support adding MeterModification.
func (m *ofMeter) Add() error {
	msg := m.ofctrl.GetBundleMessage(openflow15.MC_ADD)
	return m.ofctrl.Switch.Send(msg.GetMessage())
}

func (m *ofMeter) Modify() error {
	msg := m.ofctrl.GetBundleMessage(openflow15.MC_MODIFY)
	return m.ofctrl.Switch.Send(msg.GetMessage())
}

func (m *ofMeter) Delete() error {
	meterMod := openflow15.NewMeterMod()
	meterMod.MeterId = m.ofctrl.ID
	meterMod.Command = openflow15.MC_DELETE
	return m.ofctrl.Switch.Send(meterMod)
}

func (m *ofMeter) Type() EntryType {
	return MeterEntry
}

func (m *ofMeter) GetBundleMessages(entryOper OFOperation) ([]ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow15.MC_ADD
	case ModifyMessage:
		operation = openflow15.MC_MODIFY
	case DeleteMessage:
		operation = openflow15.MC_DELETE
	}
	message := m.ofctrl.GetBundleMessage(operation)
	return []ofctrl.OpenFlowModMessage{message}, nil
}

func (m *ofMeter) ResetMeterBands() Meter {
	m.ofctrl.MeterBands = nil
	return m
}

func (m *ofMeter) MeterBand() MeterBandBuilder {
	return &meterBandBuilder{
		meter:           m,
		meterBandHeader: openflow15.NewMeterBandHeader(),
		prevLevel:       0,
		experimenter:    0,
	}
}

type meterBandBuilder struct {
	meter           *ofMeter
	meterBandHeader *openflow15.MeterBandHeader
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
		mbDrop := new(openflow15.MeterBandDrop)
		mbDrop.MeterBandHeader = *m.meterBandHeader
		mb = mbDrop
	case uint16(ofctrl.MeterDSCPRemark):
		mbDscp := new(openflow15.MeterBandDSCP)
		mbDscp.MeterBandHeader = *m.meterBandHeader
		mbDscp.PrecLevel = m.prevLevel
		mb = mbDscp
	case uint16(ofctrl.MeterExperimenter):
		mbExp := new(openflow15.MeterBandExperimenter)
		mbExp.MeterBandHeader = *m.meterBandHeader
		mbExp.Experimenter = m.experimenter
		mb = mbExp
	}
	m.meter.ofctrl.AddMeterBand(&mb)
	return m.meter
}
