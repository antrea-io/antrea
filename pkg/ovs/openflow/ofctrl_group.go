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

package openflow

import (
	"fmt"
	"net"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
)

type ofGroup struct {
	ofctrl       *ofctrl.Group
	bridge       *OFBridge
	bucketsCount int
}

// Reset creates a new ofctrl.Group object for the updated ofSwitch. The
// ofSwitch keeps a list of all Group objects, so this operation is
// needed. Reset() should be called before replaying the Group to OVS.
func (g *ofGroup) Reset() {
	// An error ("group already exists") is not possible here since we are
	// using a new instance of ofSwitch and re-creating a group which was
	// created successfully before. There will be no duplicate group IDs. If
	// something is wrong and there is an error, g.ofctrl will be set to nil
	// and the Agent will crash later.
	newGroup, _ := g.bridge.ofSwitch.NewGroup(g.ofctrl.ID, g.ofctrl.GroupType)
	newGroup.Buckets = g.ofctrl.Buckets
	g.ofctrl = newGroup
}

func (g *ofGroup) Add() error {
	return g.ofctrl.Install()
}

func (g *ofGroup) Modify() error {
	return g.ofctrl.Install()
}

func (g *ofGroup) Delete() error {
	return g.ofctrl.Delete()
}

func (g *ofGroup) Type() EntryType {
	return GroupEntry
}

func (g *ofGroup) KeyString() string {
	return fmt.Sprintf("group_id:%d", g.ofctrl.ID)
}

func (g *ofGroup) Bucket() BucketBuilder {
	id := uint32(len(g.ofctrl.Buckets))
	return &bucketBuilder{
		group:  g,
		bucket: openflow15.NewBucket(id),
	}
}

func (g *ofGroup) GetBundleMessage(entryOper OFOperation) (ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow15.OFPGC_ADD
	case ModifyMessage:
		operation = openflow15.OFPGC_MODIFY
	case DeleteMessage:
		operation = openflow15.OFPGC_DELETE
	}
	message := g.ofctrl.GetBundleMessage(operation)
	return message, nil
}

func (g *ofGroup) ResetBuckets() Group {
	g.ofctrl.Buckets = nil
	return g
}

type bucketBuilder struct {
	group  *ofGroup
	bucket *openflow15.Bucket
}

// LoadReg makes the learned flow to load data to reg[regID] with specific range.
func (b *bucketBuilder) LoadReg(regID int, data uint32) BucketBuilder {
	return b.LoadRegRange(regID, data, &Range{0, 31})
}

// LoadXXReg makes the learned flow to load data to xxreg[regID] with specific range.
func (b *bucketBuilder) LoadXXReg(regID int, data []byte) BucketBuilder {
	field, _ := openflow15.FindFieldHeaderByName(fmt.Sprintf("NXM_NX_XXREG%d", regID), false)
	field.Value = util.NewBuffer(data)
	b.bucket.AddAction(openflow15.NewActionSetField(*field))
	return b
}

// LoadRegRange is an action to load data to the target register at specified range.
func (b *bucketBuilder) LoadRegRange(regID int, data uint32, rng *Range) BucketBuilder {
	valueData := data
	mask := uint32(0)
	if rng != nil {
		mask = ^mask >> (32 - rng.Length()) << rng.Offset()
		valueData = valueData << rng.Offset()
	}
	tgtField := openflow15.NewRegMatchFieldWithMask(regID, valueData, mask)
	b.bucket.AddAction(openflow15.NewActionSetField(*tgtField))
	return b
}

func (b *bucketBuilder) LoadToRegField(field *RegField, data uint32) BucketBuilder {
	valueData := data
	mask := uint32(0)
	if field.rng != nil {
		mask = ^mask >> (32 - field.rng.Length()) << field.rng.Offset()
		valueData = valueData << field.rng.Offset()
	}
	tgtField := openflow15.NewRegMatchFieldWithMask(field.regID, valueData, mask)
	b.bucket.AddAction(openflow15.NewActionSetField(*tgtField))
	return b
}

func (b *bucketBuilder) LoadRegMark(mark *RegMark) BucketBuilder {
	return b.LoadToRegField(mark.field, mark.value)
}

// ResubmitToTable is an action to resubmit packet to the specified table when the bucket is selected.
func (b *bucketBuilder) ResubmitToTable(tableID uint8) BucketBuilder {
	b.bucket.AddAction(openflow15.NewNXActionResubmitTableAction(openflow15.OFPP_IN_PORT, tableID))
	return b
}

// SetTunnelDst is an action to set tunnel destination address when the bucket is selected.
func (b *bucketBuilder) SetTunnelDst(addr net.IP) BucketBuilder {
	setTunDstAct := &ofctrl.SetTunnelDstAction{IP: addr}
	b.bucket.AddAction(setTunDstAct.GetActionMessage())
	return b
}

// Weight sets the weight of a bucket.
func (b *bucketBuilder) Weight(val uint16) BucketBuilder {
	weight := openflow15.NewGroupBucketPropWeight(val)
	b.bucket.AddProperty(weight)
	return b
}

func (b *bucketBuilder) Done() Group {
	b.group.ofctrl.AddBuckets(b.bucket)
	return b.group
}
