package ovsconfig

import (
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovshelper"
)

type BaseInterface ovshelper.Interface
type BasePort ovshelper.Port

type Port struct {
	BasePort
	ExternalIDs []interface{} `json:"external_ids,omitempty"`
}

type Interface struct {
	BaseInterface
	Type string `json:"type,omitempty"`
}
