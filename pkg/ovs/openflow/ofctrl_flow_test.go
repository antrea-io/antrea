package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testField = NewRegField(1, 0, 15, "testField")
	t0        = uint8(0)
	t1        = uint8(1)
)

func TestCopyToBuilder(t *testing.T) {
	table := &ofTable{
		id:   t0,
		next: t1,
	}
	mark := NewCTMark(12345, 0, 31)
	oriFlow := table.BuildFlow(uint16(100)).MatchProtocol(ProtocolIP).
		Cookie(uint64(1004)).
		MatchRegFieldWithValue(testField, 0x101).
		MatchCTStateNew(true).MatchCTStateTrk(true).
		Action().CT(
		true,
		t1,
		0x1234).
		LoadToCtMark(mark).
		MoveToLabel(NxmFieldSrcMAC, &Range{0, 47}, &Range{0, 47}).CTDone().
		Done()
	newFlow := oriFlow.CopyToBuilder(0, false)
	assert.Equal(t, oriFlow.MatchString(), newFlow.Done().MatchString())
	assert.Equal(t, oriFlow.(*ofFlow).Match, newFlow.Done().(*ofFlow).Match)
	newPriority := uint16(200)
	newFlow2 := oriFlow.CopyToBuilder(newPriority, false)
	assert.Equal(t, newPriority, newFlow2.Done().(*ofFlow).Match.Priority)
}

func TestCopyToBuilder_Drop(t *testing.T) {
	table := &ofTable{
		id:   t0,
		next: t1,
	}
	oriFlow := table.BuildFlow(uint16(100)).MatchProtocol(ProtocolIP).
		Cookie(uint64(1004)).
		MatchRegFieldWithValue(testField, 0x101).
		MatchCTStateNew(true).MatchCTStateTrk(true).
		Action().Drop().
		Done()
	newFlow := oriFlow.CopyToBuilder(0, false)
	assert.Equal(t, oriFlow.MatchString(), newFlow.Done().MatchString())
	assert.Equal(t, oriFlow.(*ofFlow).Match, newFlow.Done().(*ofFlow).Match)
	assert.Equal(t, false, newFlow.Done().IsDropFlow())
	newPriority := uint16(200)
	newFlow2 := oriFlow.CopyToBuilder(newPriority, true)
	assert.Equal(t, newPriority, newFlow2.Done().(*ofFlow).Match.Priority)
	assert.Equal(t, true, newFlow2.Done().IsDropFlow())
}
