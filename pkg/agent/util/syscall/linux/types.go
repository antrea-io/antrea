//go:build ignore
// +build ignore

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

/*
include <linux/mroute.h>
include <linux/mroute6.h>

// copied from /uapi/linux/mroute.h
// The original struct has union of vifc_lcl_addr and vifc_lcl_ifindex.
// We only want to vifc_lcl_ifindex here
struct vifctl_with_ifindex {
	vifi_t	vifc_vifi;
	unsigned char vifc_flags;
	unsigned char vifc_threshold;
	unsigned int vifc_rate_limit;
	int            vifc_lcl_ifindex;
	struct in_addr vifc_rmt_addr;
};
*/
import "C"

// These consts and structs are copied from linux kernel under linux/include/uapi/linux/mroute.h
// and are used by Antrea IPv4 multicast implementation.
const (
	IGMPMSG_NOCACHE  = C.IGMPMSG_NOCACHE
	VIFF_USE_IFINDEX = C.VIFF_USE_IFINDEX
	MRT_ADD_VIF      = C.MRT_ADD_VIF
	MRT_ADD_MFC      = C.MRT_ADD_MFC
	MRT_DEL_MFC      = C.MRT_DEL_MFC
	MRT_INIT         = C.MRT_INIT
	MRT_TABLE        = C.MRT_TABLE
	MRT_FLUSH        = C.MRT_FLUSH
	MAXVIFS          = C.MAXVIFS
)

type Mfcctl C.struct_mfcctl
type Vifctl C.struct_vifctl_with_ifindex

const SizeofMfcctl = C.sizeof_struct_mfcctl
const SizeofVifctl = C.sizeof_struct_vifctl_with_ifindex
const SizeofIgmpmsg = C.sizeof_struct_igmpmsg

// These consts and structs are copied from from linux kernel under linux/include/uapi/linux/mroute6.h
// and are used by Antrea IPv6 multicast implementation.
const (
	MRT6MSG_NOCACHE = C.MRT6MSG_NOCACHE
	MRT6_ADD_VIF    = C.MRT_ADD_VIF
	MRT6_ADD_MFC    = C.MRT_ADD_MFC
	MRT6_DEL_MFC    = C.MRT_DEL_MFC
	MRT6_INIT       = C.MRT_INIT
	MRT6_TABLE      = C.MRT_TABLE
	MRT6_FLUSH      = C.MRT_FLUSH
	MAXMIFS         = C.MAXMIFS
)

type Mfc6ctl C.struct_mif6ctl
type Vif6ctl C.struct_mf6cctl

const SizeofMif6ctl = C.sizeof_struct_mif6ctl
const SizeofMf6cctl = C.sizeof_struct_mf6cctl
const SizeofMrt6msg = C.sizeof_struct_mrt6msg
