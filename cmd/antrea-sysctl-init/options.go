//go:build linux
// +build linux

// Copyright 2025 Antrea Authors
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

package main

import (
	"fmt"

	"github.com/spf13/pflag"
)

type options struct {
	// Name of the interface that antrea-agent creates for host <-> Pod communication.
	// The rp_filter of the interface should be set to loose mode (2) for feature Egress in hybrid mode.
	hostGatewayName string
}

func newOptions() *options {
	return &options{}
}

func (o *options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.hostGatewayName, "host-gateway-name", "antrea-gw0", "Name of the Antrea host gateway interface")
}

func (o *options) validate() error {
	if o.hostGatewayName == "" {
		return fmt.Errorf("host-gateway-name must be specified")
	}
	return nil
}
