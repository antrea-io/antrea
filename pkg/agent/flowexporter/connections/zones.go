package connections

import "antrea.io/antrea/pkg/agent/openflow"

type ZoneGetter struct {
	v4Enabled bool
	v6Enabled bool

	connectUplinkToBridge bool
}

func (z ZoneGetter) Get() []uint16 {
	var zones []uint16

	if z.v4Enabled {
		if z.connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPCtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZone)
		}
	}
	if z.v6Enabled {
		if z.connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPv6CtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZoneV6)
		}
	}

	return zones
}
