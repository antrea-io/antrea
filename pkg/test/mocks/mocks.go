// Copyright 2019 OKN Authors
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

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -destination ovsconfig_mock.go -package=mocks -mock_names OVSBridgeClient=MockOVSBridgeClient okn/pkg/ovs/ovsconfig OVSBridgeClient
//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -destination ipam_mock.go -package=mocks okn/pkg/agent/cniserver/ipam IPAMDriver
//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -destination ofclient_mock.go -package=mocks -mock_names Client=MockOFClient okn/pkg/agent/openflow Client

package mocks
