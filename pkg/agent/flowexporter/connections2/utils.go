package connections2

import (
	"encoding/binary"
	"net/netip"
)

func ipFromArr(a [16]byte) netip.Addr {
	// Try IPv4 first
	if isIPv4(a) {
		return netip.AddrFrom4([4]byte{a[12], a[13], a[14], a[15]})
	}
	return netip.AddrFrom16(a)
}
func isIPv4(a [16]byte) bool {
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0 &&
		a[8] == 0 && a[9] == 0 && a[10] == 0 && a[11] == 0 && !(a[12] == 0 && a[13] == 0 && a[14] == 0 && a[15] == 0)
}

// helper to create deterministic-ish IPs
func ipFromInt(i uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], i)
	return netip.AddrFrom4(b)
}
