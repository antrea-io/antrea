package exporter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
)

func TestIPFIXExporter_DeltaCalculation(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	flowExp := &ipfixExporter{
		process:        mockIPFIXExpProc,
		elementsListv4: getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4),
		templateIDv4:   testTemplateIDv4,
		registry:       mockIPFIXRegistry,
		v4Enabled:      true,
		ipfixSet:       mockDataSet,
	}

	// Helper to find value in ElementListMatcher
	getValue := func(name string, elements []ipfixentities.InfoElementWithValue) uint64 {
		for _, ie := range elements {
			if ie.GetInfoElement().Name == name {
				return ie.GetUnsigned64Value()
			}
		}
		return 0
	}

	tests := []struct {
		name            string
		originalPackets uint64
		prevPackets     uint64
		expectedDelta   uint64
		originalBytes   uint64
		prevBytes       uint64
		expectedBytes   uint64
	}{
		{
			name:            "Normal increase",
			originalPackets: 100,
			prevPackets:     90,
			expectedDelta:   10,
			originalBytes:   1000,
			prevBytes:       900,
			expectedBytes:   100,
		},
		{
			name:            "Large value (potential overflow in int64)",
			originalPackets: uint64(1<<63) + 100, // > MaxInt64
			prevPackets:     uint64(1 << 63),
			expectedDelta:   100,
			originalBytes:   uint64(1<<63) + 1000,
			prevBytes:       uint64(1 << 63),
			expectedBytes:   1000,
		},
		{
			name:            "Very large delta (overflow int64)",
			originalPackets: uint64(1<<63) + 100,
			prevPackets:     0,
			expectedDelta:   uint64(1<<63) + 100,
			originalBytes:   uint64(1<<63) + 1000,
			prevBytes:       0,
			expectedBytes:   uint64(1<<63) + 1000,
		},
		// Case: counter reset (Original < Prev)
		// Logic: Original - Prev (wrap around)
		{
			name:            "Counter reset (negative delta)",
			originalPackets: 10,
			prevPackets:     20,
			expectedDelta:   ^uint64(0) - 9, // -10 wrapped
			originalBytes:   100,
			prevBytes:       200,
			expectedBytes:   ^uint64(0) - 99, // -100 wrapped
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &connection.Connection{
				OriginalPackets: tc.originalPackets,
				PrevPackets:     tc.prevPackets,
				OriginalBytes:   tc.originalBytes,
				PrevBytes:       tc.prevBytes,
				FlowKey:         connection.Tuple{SourceAddress: netip.MustParseAddr("1.1.1.1"), DestinationAddress: netip.MustParseAddr("2.2.2.2")},
			}

			mockDataSet.EXPECT().ResetSet()
			mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, testTemplateIDv4).Return(nil)
			mockDataSet.EXPECT().AddRecordV2(gomock.Any(), testTemplateIDv4).DoAndReturn(
				func(elements []ipfixentities.InfoElementWithValue, templateID uint16) error {
					deltaPkts := getValue("packetDeltaCount", elements)
					deltaBytes := getValue("octetDeltaCount", elements)
					assert.Equal(t, tc.expectedDelta, deltaPkts, "packetDeltaCount mismatch")
					assert.Equal(t, tc.expectedBytes, deltaBytes, "octetDeltaCount mismatch")
					return nil
				})

			err := flowExp.addConnToSet(conn)
			assert.NoError(t, err)
		})
	}
}
