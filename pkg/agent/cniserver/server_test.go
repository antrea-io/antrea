package cniserver

import (
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/google/uuid"
	"k8s.io/klog"
	"okn/pkg/agent/cniserver/ipam"
	"okn/pkg/apis/cni"
)

const (
	netns     = "ns-1"
	ifname    = "eth0"
	testScock = "/tmp/test.sock"
)

var testIPAMService *TestIPAMService

type TestIPAMService struct {
	t      *testing.T
	Result *current.Result
	gws    []net.IP
}

func (s *TestIPAMService) Add(args *invoke.Args, networkConfig []byte) (*current.Result, error) {
	var requsestCfg = &NetworkConfig{}
	if err := json.Unmarshal(networkConfig, &requsestCfg); err != nil {
		s.t.Error("Failed to resolve configuration")
	}
	ipamResult := &current.Result{}
	ipamResult.CNIVersion = requsestCfg.CNIVersion
	ipamResult.IPs = make([]*current.IPConfig, 0)
	_, ipv4Net, err := net.ParseCIDR("10.1.2.2/24")
	if ipv4Net == nil || err != nil {
		s.t.Fatal("Failed to parse ipv4 configuration")
	}
	net4Gw := net.ParseIP("10.1.2.1")
	ipamResult.IPs = append(ipamResult.IPs, &current.IPConfig{Version: "4", Address: *ipv4Net, Gateway: net4Gw})
	_, ipv6Net, err := net.ParseCIDR("2001:db8:1::2/64")
	if err != nil {
		s.t.Fatal("Failed to parse ipv6 configuration")
	}
	net6Gw := net.ParseIP("2001:db8:1::1")
	ipamResult.IPs = append(ipamResult.IPs, &current.IPConfig{Version: "4", Address: *ipv6Net, Gateway: net6Gw})
	ipamResult.Routes = make([]*types.Route, 0)
	_, route1, _ := net.ParseCIDR("0.0.0.0/0")
	_, route2, _ := net.ParseCIDR("::/0")
	_, route3, _ := net.ParseCIDR("192.168.0.0/16")
	gw3 := net.ParseIP("1.1.1.1")
	_, route4, _ := net.ParseCIDR("2001:db8:2::/64")
	gw4 := net.ParseIP("2001:db8:3::1")
	ipamResult.Routes = append(ipamResult.Routes, &types.Route{Dst: *route1}, &types.Route{Dst: *route2},
		&types.Route{Dst: *route3, GW: gw3}, &types.Route{Dst: *route4, GW: gw4})
	ipamResult.DNS = types.DNS{Nameservers: []string{"192.0.2.3"}}
	s.Result = ipamResult
	s.gws = make([]net.IP, 0)
	s.gws = append(s.gws, net4Gw)
	s.gws = append(s.gws, net6Gw)
	return ipamResult, nil
}

func (s *TestIPAMService) Del(args *invoke.Args, networkConfig []byte) error {
	s.t.Logf("Del is invoked")
	return nil
}

func (s *TestIPAMService) Check(args *invoke.Args, networkConfig []byte) error {
	s.t.Logf("Check is invoked")
	return nil
}

func (s *TestIPAMService) GetIpamType() string {
	return "test"
}

func createTestIpamService() *TestIPAMService {
	testIpam := &TestIPAMService{}
	if err := ipam.RegisterIPAMDriver("test", testIpam); err != nil {
		klog.Errorf("Failed to register IPAMDriver with type test")
		os.Exit(1)
	}
	return testIpam
}

func init() {
	testIPAMService = createTestIpamService()
}

func TestLoadNetConfig(t *testing.T) {
	cniService := generateCNIServer(t)
	var version = "0.5.1"
	networkCfg := generateNetworkConfiguration("testCfg", version)
	requestMsg, containerId := newRequest(version, "", networkCfg, "", t)
	netCfg, err := cniService.loadNetworkConfig(&requestMsg)
	if err != nil {
		t.Errorf("Found error while parsing request message, %v", err)
	}
	reqVersion := netCfg.CNIVersion
	if (reqVersion != version) || reqVersion != netCfg.CNIVersion {
		t.Error("Failed to parse version from request")
	}
	if netCfg.ContainerId != containerId {
		t.Error("Failed to parse ContainerId")
	}
	if netCfg.Netns != netns {
		t.Error("Failed to parse netns")
	}
	if netCfg.Ifname != ifname {
		t.Error("Failed to parse ifname")
	}
	if netCfg.Name != networkCfg.Name {
		t.Error("Failed to parse network configuration")
	}
	if netCfg.IPAM.Type != networkCfg.IPAM.Type {
		t.Error("Failed to parse network configuration")
	}
}

func TestRequestCheck(t *testing.T) {
	cniService := generateCNIServer(t)
	var version1 = "0.5.1"
	valid := cniService.isCNIVersionSupported(version1)
	if valid {
		t.Error("Failed to check version")
	}
	var version2 = "0.4.0"
	valid = cniService.isCNIVersionSupported(version2)
	if !valid {
		t.Error("Failed to support version")
	}
}

func TestNewCNIServer(t *testing.T) {
	testSupportedVersionStr := "0.3.0, 0.3.1, 0.4.0"
	var supporteVersions = []string{"0.3.0", "0.3.1", "0.4.0"}
	cniServer, err := New(testScock)
	if err != nil {
		t.Errorf("Failed to New cni Server")
	} else {
		cniServer.supportedCNIVersions = buildVersionSet(testSupportedVersionStr)
		for _, ver := range supporteVersions {
			if !cniServer.isCNIVersionSupported(ver) {
				t.Errorf("CniService init failed for wrong supportedCNIVersions")
			}
		}
		isValid := ipam.IsIPAMTypeValid("test")
		if !isValid {
			t.Errorf("Failed to load Ipam service")
		}
		isValid = ipam.IsIPAMTypeValid("test1")
		if isValid {
			t.Errorf("Failed to register Ipam service")
		}
	}
}

func TestCheckRequestMessage(t *testing.T) {
	cniService := generateCNIServer(t)
	networkCfg := generateNetworkConfiguration("testCfg", "0.3.1")
	requestMsg, _ := newRequest("2.0", "", networkCfg, "", t)
	_, response := cniService.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION {
		t.Errorf("Failed to identify incompatible request version from client")
	}

	networkCfg = generateNetworkConfiguration("testCfg", "0.5.1")
	requestMsg, _ = newRequest("1.0", "", networkCfg, "", t)
	_, response = cniService.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_INCOMPATIBLE_CNI_VERSION {
		t.Errorf("Failed to identify incompatible CNI version from request")
	}

	networkCfg = generateNetworkConfiguration("testCfg", "0.3.1")
	networkCfg.IPAM.Type = "unknown"
	requestMsg, _ = newRequest("1.0", "", networkCfg, "", t)
	_, response = cniService.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION {
		t.Errorf("Failed to identify unsupported network configuration")
	}
}

func generateCNIServer(t *testing.T) *CNIServer {
	supportedVersions := "0.3.0,0.3.1,0.4.0"
	cniServer := &CNIServer{
		cniSocket:            testScock,
		supportedCNIVersions: buildVersionSet(supportedVersions),
	}
	return cniServer
}

func generateNetworkConfiguration(name string, cniVersion string) *types.NetConf {
	netCfg := &types.NetConf{}
	netCfg.Name = name
	netCfg.CNIVersion = cniVersion
	netCfg.Type = "okn"
	netCfg.IPAM = types.IPAM{Type: "host-local"}
	return netCfg
}

func newRequest(reqVersion string, args string, netCfg *types.NetConf, path string, t *testing.T) (cnimsg.CniCmdRequestMessage, string) {
	containerId := generateUUID(t)
	networkConfig, err := json.Marshal(netCfg)
	if err != nil {
		t.Error("Failed to generateNetowrk")
	}

	cmdRequest := cnimsg.CniCmdRequestMessage{
		CniArgs: &cnimsg.CniCmdArgsMessage{
			ContainerId:          containerId,
			Ifname:               ifname,
			Args:                 args,
			Netns:                netns,
			NetworkConfiguration: networkConfig,
			Path:                 path,
		},
		Version: reqVersion,
	}
	return cmdRequest, containerId
}

func generateUUID(t *testing.T) string {
	newId, err := uuid.NewUUID()
	if err != nil {
		t.Fatal("Failed to generate UUID")
	}
	return newId.String()
}
