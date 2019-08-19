package ovsconfig

const (
	GENEVE_TUNNEL = "geneve"
	VXLAN_TUNNEL  = "vxlan"
)

type OVSBridgeClient interface {
	Create() Error
	Delete() Error
	CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error)
	CreateGenevePort(name string, ofPortRequest int32, remoteIP string) (string, Error)
	CreateInternalPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error)
	CreateVXLANPort(name string, ofPortRequest int32, remoteIP string) (string, Error)
	DeletePort(portUUID string) Error
	DeletePorts(portUUIDList []string) Error
	GetOFPort(ifName string) (int32, Error)
	GetPortData(portUUID, ifName string) (*OVSPortData, Error)
	GetPortList() ([]OVSPortData, Error)
}
