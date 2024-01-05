// Copyright 2021 Antrea Authors
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

package ipassigner

import (
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// IPAssigner provides methods to assign or unassign IP.
type IPAssigner interface {
	// AssignIP ensures the provided IP is assigned to the system.
	// It returns true only in the case when there is no error and the IP provided
	// was not assigned to the interface before the operation, in all other cases it
	// returns false.
	AssignIP(ip string, subnetInfo *v1beta1.SubnetInfo, forceAdvertise bool) (bool, error)
	// UnassignIP ensures the provided IP is not assigned to the system.
	// It returns true only in the case when there is no error and the IP provided
	// was assigned to the interface before the operation.
	UnassignIP(ip string) (bool, error)
	// AssignedIPs return the IPs that are assigned to the system by this IPAssigner.
	AssignedIPs() map[string]*v1beta1.SubnetInfo
	// InitIPs ensures the IPs that are assigned to the system match the given IPs.
	InitIPs(map[string]*v1beta1.SubnetInfo) error
	// GetInterfaceID returns the index of the network interface to which IPs in the provided subnet are assigned.
	GetInterfaceID(subnetInfo *v1beta1.SubnetInfo) (int, bool)
	// Run starts the IP assigner.
	Run(<-chan struct{})
}
