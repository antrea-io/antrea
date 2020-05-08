package connections

import (
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
)

// ConnTrackPoller is an interface that is used to poll and dump connections from
// conntrack module.
type ConnTrackPoller interface {
	DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error)
}
