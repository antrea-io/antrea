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

var (
	MaxBucketsPerMessage = 700
)

type ofGroup struct {
	ofctrl *ofctrl.Group
	bridge *OFBridge
}

// Reset updates ofctrl.Group.Switch with the updated ofSwitch.
func (g *ofGroup) Reset() {
	g.ofctrl.Switch = g.bridge.ofSwitch
}

func (g *ofGroup) Add() error {
	return g.bridge.AddOFEntriesInBundle([]OFEntry{g}, nil, nil)
}

func (g *ofGroup) Modify() error {
	return g.bridge.AddOFEntriesInBundle(nil, []OFEntry{g}, nil)
}

func (g *ofGroup) Delete() error {
	return g.bridge.AddOFEntriesInBundle(nil, nil, []OFEntry{g})
}

func (g *ofGroup) Type() EntryType {
	return GroupEntry
}

func (g *ofGroup) Bucket() BucketBuilder {
	id := uint32(len(g.ofctrl.Buckets))
	return &bucketBuilder{
		group:  g,
		bucket: openflow15.NewBucket(id),
	}
}

func (g *ofGroup) GetBundleMessages(entryOper OFOperation) ([]ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow15.OFPGC_ADD
	case ModifyMessage:
		operation = openflow15.OFPGC_MODIFY
	case DeleteMessage:
		operation = openflow15.OFPGC_DELETE
		// If the operation is to delete the group, empty the slice storing buckets since the number of buckets could
		// be greater than MaxBucketsPerMessage.
		g.ofctrl.Buckets = nil
	}

	var messages []ofctrl.OpenFlowModMessage
	for start := 0; start <= len(g.ofctrl.Buckets); start += MaxBucketsPerMessage {
		// Get the range of buckets to generate a temp group.
		end := start + MaxBucketsPerMessage
		if end > len(g.ofctrl.Buckets) {
			end = len(g.ofctrl.Buckets)
		}
		// For the message which is not the first, insert_buckets is used to add buckets to the group on OVS.
		if start != 0 {
			operation = openflow15.OFPGC_INSERT_BUCKET
			// There is no need to generate an insert_buckets message without bucket.
			if start == end {
				break
			}
		}
		// Generate a temp group to get an OVS message. Note that, the original group should not be modified since it is
		// also stored in group cache, and the group cache is used when replaying groups.
		groupMessage := &ofctrl.Group{
			ID:        g.ofctrl.ID,
			GroupType: g.ofctrl.GroupType,
			Buckets:   g.ofctrl.Buckets[start:end],
		}

		messages = append(messages, groupMessage.GetBundleMessage(operation))
	}
	return messages, nil
}

func (g *ofGroup) ResetBuckets() Group {
	g.ofctrl.Buckets = nil
	return g
}

func (g *ofGroup) GetID() GroupIDType {
	return GroupIDType(g.ofctrl.ID)
}

type bucketBuilder struct {
	group  *ofGroup
	bucket *openflow15.Bucket
}

// LoadXXReg makes the learned flow to load data to xxreg[regID] with specific range.
func (b *bucketBuilder) LoadXXReg(regID int, data []byte) BucketBuilder {
	field, _ := openflow15.FindFieldHeaderByName(fmt.Sprintf("NXM_NX_XXREG%d", regID), false)
	field.Value = util.NewBuffer(data)
	b.bucket.AddAction(openflow15.NewActionSetField(*field))
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
	b.group.ofctrl.Buckets = append(b.group.ofctrl.Buckets, b.bucket)
	return b.group
}
