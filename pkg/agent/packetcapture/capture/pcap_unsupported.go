//go:build !linux
// +build !linux

// Copyright 2024 Antrea Authors.
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

package capture

import (
	"context"
	"errors"
	"net"

	"github.com/gopacket/gopacket"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type pcapCapture struct {
}

func NewPcapCapture() (*pcapCapture, error) {
	return nil, errors.New("PacketCapture is not implemented")
}

func (p *pcapCapture) Capture(ctx context.Context, device string, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet) (chan gopacket.Packet, error) {
	return nil, errors.New("PacketCapture is not implemented")
}
