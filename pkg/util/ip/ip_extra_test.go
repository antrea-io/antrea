package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMustParseMAC(t *testing.T) {
	tests := []struct {
		name        string
		mac         string
		expectedMAC string
		shouldPanic bool
	}{
		{
			name:        "valid MAC",
			mac:         "aa:bb:cc:dd:ee:ff",
			expectedMAC: "aa:bb:cc:dd:ee:ff",
			shouldPanic: false,
		},
		{
			name:        "invalid MAC",
			mac:         "invalid-mac",
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(t, func() { MustParseMAC(tt.mac) })
			} else {
				mac := MustParseMAC(tt.mac)
				assert.Equal(t, tt.expectedMAC, mac.String())
			}
		})
	}
}

func TestGetLocalBroadcastIP(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		expectedIP string
	}{
		{
			name:       "IPv4 /24",
			cidr:       "192.168.1.0/24",
			expectedIP: "192.168.1.255",
		},
		{
			name:       "IPv4 /16",
			cidr:       "10.0.0.0/16",
			expectedIP: "10.0.255.255",
		},
		{
			name:       "IPv4 /30",
			cidr:       "10.10.10.0/30",
			expectedIP: "10.10.10.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, _ := net.ParseCIDR(tt.cidr)
			broadcastIP := GetLocalBroadcastIP(ipNet)
			assert.Equal(t, tt.expectedIP, broadcastIP.String())
		})
	}
}
