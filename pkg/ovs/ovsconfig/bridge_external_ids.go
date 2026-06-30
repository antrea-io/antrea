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
	"fmt"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
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
		bridges = append(bridges, OVSBridgeData{Name: rows[i].Name, ExternalIDs: rows[i].ExternalIDs})
	}
	return bridges, nil
}

// GetOVSBridgeExternalIDs returns the external IDs for an OVS bridge.
func GetOVSBridgeExternalIDs(ovsdbClient client.Client, bridgeName string) (map[string]string, bool, error) {
	bridge := &Bridge{Name: bridgeName}
	err := ovsdbClient.Get(context.TODO(), bridge)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return bridge.ExternalIDs, true, nil
}

// SetOVSBridgeExternalIDs sets the external IDs for an OVS bridge.
func SetOVSBridgeExternalIDs(ovsdbClient client.Client, bridgeName string, externalIDs map[string]string) error {
	ctx := context.TODO()
	bridge := &Bridge{Name: bridgeName}
	if err := ovsdbClient.Get(ctx, bridge); err != nil {
		return err
	}

	updateBridge := &Bridge{ExternalIDs: externalIDs}
	ops, err := ovsdbClient.Where(&Bridge{UUID: bridge.UUID}).Update(updateBridge, &updateBridge.ExternalIDs)
	if err != nil {
		return err
	}
	results, err := ovsdbClient.Transact(ctx, ops...)
	if err != nil {
		return err
	}
	opErrs, err := ovsdb.CheckOperationResults(results, ops)
	if err != nil {
		return convertOVSDBErrors(opErrs, fmt.Errorf("failed to set external IDs for OVS bridge %s: %w", bridgeName, err))
	}
	return nil
}
