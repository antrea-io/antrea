package ovsconfig

// OVSBridgeClient is an interface for ovsdb client, which could be used in unit tests to construct mock instances
type OVSBridgeClient interface {
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
