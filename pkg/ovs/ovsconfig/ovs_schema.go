package ovsconfig

type Port struct {
	Name        string        `json:"name"`
	Interfaces  []interface{} `json:"interfaces"`
	ExternalIDs []interface{} `json:"external_ids,omitempty"`
}

type Interface struct {
	Name          string        `json:"name"`
	Type          string        `json:"type,omitempty"`
	OFPortRequest int32         `json:"ofport_request,omitempty"`
	Options       []interface{} `json:"options,omitempty"`
}
