// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovsconfig

import (
	"context"
	"errors"
	"maps"

	"github.com/ovn-kubernetes/libovsdb/client"
	"k8s.io/klog/v2"
)

type OVSBridgeData struct {
	Name        string
	ExternalIDs map[string]string
}

// ListOVSBridges returns all OVS bridges with their external IDs.
func ListOVSBridges(ovsdbClient client.Client) ([]OVSBridgeData, error) {
	var rows []Bridge
	err := ovsdbClient.List(context.TODO(), &rows)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return nil, nil
		}
		klog.ErrorS(err, "Failed to list OVSDB Bridge rows")
		return nil, err
	}

	bridges := make([]OVSBridgeData, 0, len(rows))
	for i := range rows {
		bridges = append(bridges, OVSBridgeData{Name: rows[i].Name, ExternalIDs: maps.Clone(rows[i].ExternalIDs)})
	}
	return bridges, nil
}
