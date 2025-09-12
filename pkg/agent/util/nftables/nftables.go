package nftables

import "sigs.k8s.io/knftables"

const antreaTable = "antrea"

func New(enableIPv4, enableIPv6 bool) (knftables.Interface, error) {
	var ipFamily knftables.Family
	if enableIPv4 && enableIPv6 {
		ipFamily = knftables.InetFamily
	} else if enableIPv4 {
		ipFamily = knftables.IPv4Family
	} else if enableIPv6 {
		ipFamily = knftables.IPv6Family
	}

	nft, err := knftables.New(ipFamily, antreaTable)
	if err != nil {
		return nil, err
	}

	return nft, nil
}
