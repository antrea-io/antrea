//go:build linux
// +build linux

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

package syscall

const (
	IGMPMSG_NOCACHE  = 0x1
	VIFF_USE_IFINDEX = 0x8
	MRT_ADD_VIF      = 0xca
	MRT_ADD_MFC      = 0xcc
	MRT_DEL_MFC      = 0xcd
	MRT_INIT         = 0xc8
	MRT_FLUSH        = 0xd4
	MAXVIFS          = 0x20
)

type Mfcctl struct {
	Origin   [4]byte /* in_addr */
	Mcastgrp [4]byte /* in_addr */
	Parent   uint16
	Ttls     [32]uint8
	Pkt_cnt  uint32
	Byte_cnt uint32
	Wrong_if uint32
	Expire   int32
}

type Vifctl struct {
	Vifi        uint16
	Flags       uint8
	Threshold   uint8
	Rate_limit  uint32
	Lcl_ifindex int32
	Rmt_addr    [4]byte /* in_addr */
}

const SizeofMfcctl = 0x3c
const SizeofVifctl = 0x10
const SizeofIgmpmsg = 0x14
