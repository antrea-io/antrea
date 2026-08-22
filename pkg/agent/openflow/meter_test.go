package openflow

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	ovsoftest "antrea.io/antrea/pkg/ovs/openflow/testing"
)

func TestClient_getMeterStats(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockBridge := ovsoftest.NewMockBridge(ctrl)

	c := &client{
		bridge: mockBridge,
		ovsMeterPacketDrops: map[int]*atomic.Uint64{
			PacketInMeterIDNP: {},
		},
		ovsMetersAreSupported: true,
	}

	// TestCase 1: Initial drop count
	mockBridge.EXPECT().GetMeterStats(gomock.Any()).DoAndReturn(func(handleMeterStatsReply func(int, uint64)) error {
		handleMeterStatsReply(PacketInMeterIDNP, 100)
		return nil
	})

	c.getMeterStats()
	assert.Equal(t, uint64(100), c.ovsMeterPacketDrops[PacketInMeterIDNP].Load())

	// TestCase 2: Increase drop count (no overflow)
	mockBridge.EXPECT().GetMeterStats(gomock.Any()).DoAndReturn(func(handleMeterStatsReply func(int, uint64)) error {
		handleMeterStatsReply(PacketInMeterIDNP, 200)
		return nil
	})
	c.getMeterStats()
	assert.Equal(t, uint64(200), c.ovsMeterPacketDrops[PacketInMeterIDNP].Load())

	// TestCase 3: Large drop count (overflow scenario if int64 was used)
	largeCount := uint64(1<<63 + 100) // Value larger than max int64
	mockBridge.EXPECT().GetMeterStats(gomock.Any()).DoAndReturn(func(handleMeterStatsReply func(int, uint64)) error {
		handleMeterStatsReply(PacketInMeterIDNP, largeCount)
		return nil
	})
	c.getMeterStats()
	assert.Equal(t, largeCount, c.ovsMeterPacketDrops[PacketInMeterIDNP].Load())
}
