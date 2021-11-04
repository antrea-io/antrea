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

package bandwidth

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	Kilo resource.Scale = 3
	Mega resource.Scale = 6
	Giga resource.Scale = 9
)

var minRsrc = resource.MustParse("1k")
var maxRsrc = resource.MustParse("1T")

// validateBandwidthIsReasonable returns the bandwidth is in valid scale.
func validateBandwidthIsReasonable(rsrc *resource.Quantity) error {
	if rsrc.Value() < minRsrc.Value() {
		return fmt.Errorf("resource is unreasonably small (< 1kbit)")
	}
	if rsrc.Value() > maxRsrc.Value() {
		return fmt.Errorf("resoruce is unreasonably large (> 1Tbit)")
	}
	return nil
}

// ParseBandwidth returns the bandwidth from the given string
func ParseBandwidth(bandwidthStr string, scale resource.Scale) (bandwidth uint32, err error) {
	if bandwidthStr == "" {
		return 0, nil
	}
	bandwidthValue, err := resource.ParseQuantity(bandwidthStr)
	if err != nil {
		return 0, err
	}
	if err := validateBandwidthIsReasonable(&bandwidthValue); err != nil {
		return 0, err
	}
	bandwidth = uint32(bandwidthValue.ScaledValue(scale))
	return bandwidth, nil
}
