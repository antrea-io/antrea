package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopyToBuilder(t *testing.T) {
	table := &ofTable{
		id:   0,
		next: 1,
	}
	oriFlow := table.BuildFlow(uint16(100)).MatchProtocol(ProtocolIP).
		Cookie(uint64(1004)).
		MatchRegRange(1, 0x101, Range{0, 15}).
		MatchCTStateNew(true).MatchCTStateTrk(true).
		Action().CT(
		true,
		1,
		0x1234).
		LoadToMark(uint32(12345)).
		MoveToLabel(NxmFieldSrcMAC, &Range{0, 47}, &Range{0, 47}).CTDone().
		Done()
	newFlow := oriFlow.CopyToBuilder(0)
	assert.Equal(t, oriFlow.MatchString(), newFlow.Done().MatchString())
	assert.Equal(t, oriFlow.(*ofFlow).Match, newFlow.Done().(*ofFlow).Match)
	newPriority := uint16(200)
	newFlow2 := oriFlow.CopyToBuilder(newPriority)
	assert.Equal(t, newPriority, newFlow2.Done().(*ofFlow).Match.Priority)
}
