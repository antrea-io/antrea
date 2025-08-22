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

package nftables

import (
	"context"
	"fmt"
	"iter"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

const table = "antrea"

type Client struct {
	IPv4 knftables.Interface
	IPv6 knftables.Interface
}

func (c *Client) All() iter.Seq2[knftables.Family, knftables.Interface] {
	return func(yield func(knftables.Family, knftables.Interface) bool) {
		if c.IPv4 != nil {
			if !yield(knftables.IPv4Family, c.IPv4) {
				return
			}
		}
		if c.IPv6 != nil {
			if !yield(knftables.IPv6Family, c.IPv6) {
				return
			}
		}
	}
}

func New(enableIPv4, enableIPv6 bool) (*Client, error) {
	client := &Client{}
	if enableIPv4 {
		nft, err := newNFTables(knftables.IPv4Family)
		if err != nil {
			return nil, fmt.Errorf("error creating nftables instance: %v", err)
		}
		client.IPv4 = nft
	}
	if enableIPv6 {
		nft, err := newNFTables(knftables.IPv6Family)
		if err != nil {
			return nil, fmt.Errorf("error creating nftables instance: %v", err)
		}
		client.IPv6 = nft
	}
	return client, nil
}

func newNFTables(ipFamily knftables.Family) (knftables.Interface, error) {
	// knftables.New validates:
	//  - nft binary is available
	//  - sufficient permissions
	//  - kernel version compatibility
	//  - "nft destroy" support
	nft, err := knftables.New(ipFamily, table)
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables instance: %v", err)
	}

	// Verify nft_flow_offload support with a dry-run.
	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})
	tx.Add(&knftables.Flowtable{
		Name:     "test_flowtable",
		Priority: ptr.To(knftables.FilterIngressPriority),
		Devices:  []string{"lo"},
	})
	tx.Add(&knftables.Chain{
		Name:     "test_chain",
		Type:     ptr.To(knftables.FilterType),
		Hook:     ptr.To(knftables.ForwardHook),
		Priority: ptr.To(knftables.FilterPriority),
	})
	tx.Add(&knftables.Rule{
		Chain: "test_chain",
		Rule:  knftables.Concat("flow", "add", "@", "test_flowtable"),
	})
	if err := nft.Check(context.TODO(), tx); err != nil {
		return nil, fmt.Errorf("nftables flowtable is not supported: %w", err)
	}

	return nft, nil
}
