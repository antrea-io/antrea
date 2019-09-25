package it

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"okn/pkg/agent"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"okn/pkg/agent/cniserver"
	"okn/pkg/agent/cniserver/ipam"
	cnimsg "okn/pkg/apis/cni"
	"okn/pkg/cni"
	"okn/pkg/ovs/ovsconfig"
	"okn/pkg/test"
	"okn/pkg/test/mocks"
)

const (
	IFNAME               = "eth0"
	CONTAINERID          = "dummy-0"
	testSock             = "/tmp/test.sock"
	testPod              = "test-1"
	testPodNamespace     = "t1"
	testPodInfraContaner = "test-111111"
	bridge               = "br0"
)

const (
	netConfStr = `
	"cniVersion": "%s",
	"name": "testConfig",
	"type": "okn"`

	vlan = `,
	"vlan": %d`

	netDefault = `,
	"isDefaultGateway": true`

	ipamStartStr = `,
    "ipam": {
        "type":    "mock"`

	ipamDataDirStr = `,
        "dataDir": "%s"`

	// Single subnet configuration (legacy)
	subnetConfStr = `,
        "subnet":  "%s"`
	gatewayConfStr = `,
        "gateway": "%s"`

	// Ranges (multiple subnets) configuration
	rangesStartStr = `,
        "ranges": [`
	rangeSubnetConfStr = `
            [{
                "subnet":  "%s"
            }]`
	rangeSubnetGatewayConfStr = `
            [{
                "subnet":  "%s",
                "gateway": "%s"
            }]`
	rangesEndStr = `
        ]`

	ipamEndStr = `
    }`
)

var ipamMock *mocks.MockIPAMDriver
var ovsServiceMock *mocks.MockOVSdbClient
var ofServiceMock *mocks.MockOFClient
var testNodeConfig *agent.NodeConfig

type Net struct {
	Name          string                 `json:"name"`
	CNIVersion    string                 `json:"cniVersion"`
	Type          string                 `json:"type,omitempty"`
	BrName        string                 `json:"ovsBinding"`
	IPAM          *allocator.IPAMConfig  `json:"ipam"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    current.Result         `json:"-"`
}

// Range definition for each entry in the ranges list
type rangeInfo struct {
	subnet  string
	gateway string
}

type testCase struct {
	cniVersion      string      // CNI Version
	subnet          string      // Single subnet config: Subnet CIDR
	gateway         string      // Single subnet config: Gateway
	ranges          []rangeInfo // Ranges list (multiple subnets config)
	expGatewayCIDRs []string    // Expected gateway addresses in CIDR form
	addresses       []string
	routes          []string
	dns             []string
}

func (tc testCase) netConfJSON(dataDir string) string {
	conf := fmt.Sprintf(netConfStr, tc.cniVersion)
	conf += netDefault
	if tc.subnet != "" || tc.ranges != nil {
		conf += ipamStartStr
		if dataDir != "" {
			conf += fmt.Sprintf(ipamDataDirStr, dataDir)
		}
		if tc.subnet != "" {
			conf += tc.subnetConfig()
		}
		if tc.ranges != nil {
			conf += tc.rangesConfig()
		}
		conf += ipamEndStr
	}
	return "{" + conf + "\n}"
}

func (tc testCase) subnetConfig() string {
	conf := fmt.Sprintf(subnetConfStr, tc.subnet)
	if tc.gateway != "" {
		conf += fmt.Sprintf(gatewayConfStr, tc.gateway)
	}
	return conf
}

func (tc testCase) rangesConfig() string {
	conf := rangesStartStr
	for i, tcRange := range tc.ranges {
		if i > 0 {
			conf += ","
		}
		if tcRange.gateway != "" {
			conf += fmt.Sprintf(rangeSubnetGatewayConfStr, tcRange.subnet, tcRange.gateway)
		} else {
			conf += fmt.Sprintf(rangeSubnetConfStr, tcRange.subnet)
		}
	}
	return conf + rangesEndStr
}

func (tc testCase) expectedCIDRs() ([]*net.IPNet, []*net.IPNet) {
	var cidrsV4, cidrsV6 []*net.IPNet
	appendSubnet := func(subnet string) {
		ip, cidr, err := net.ParseCIDR(subnet)
		Expect(err).NotTo(HaveOccurred())
		if ipVersion(ip) == "4" {
			cidrsV4 = append(cidrsV4, cidr)
		} else {
			cidrsV6 = append(cidrsV6, cidr)
		}
	}
	if tc.subnet != "" {
		appendSubnet(tc.subnet)
	}
	for _, r := range tc.ranges {
		appendSubnet(r.subnet)
	}
	return cidrsV4, cidrsV6
}

func (tc testCase) createCmdArgs(targetNS ns.NetNS, dataDir string) *cnimsg.CniCmdRequestMessage {
	conf := tc.netConfJSON(dataDir)
	reqVersion := cni.OKNVersion
	return &cnimsg.CniCmdRequestMessage{
		CniArgs: &cnimsg.CniCmdArgsMessage{
			ContainerId:          CONTAINERID,
			Ifname:               IFNAME,
			Netns:                targetNS.Path(),
			NetworkConfiguration: []byte(conf),
			Args:                 test.GenerateCNIArgs(testPod, testPodNamespace, testPodInfraContaner),
		},
		Version: reqVersion,
	}
}

func (tc testCase) createCheckCmdArgs(targetNS ns.NetNS, config *Net, dataDir string) *cnimsg.CniCmdRequestMessage {
	conf, err := json.Marshal(config)
	Expect(err).NotTo(HaveOccurred())

	reqVersion := cni.OKNVersion
	return &cnimsg.CniCmdRequestMessage{
		CniArgs: &cnimsg.CniCmdArgsMessage{
			ContainerId:          CONTAINERID,
			Ifname:               IFNAME,
			Netns:                targetNS.Path(),
			NetworkConfiguration: []byte(conf),
			Args:                 test.GenerateCNIArgs(testPod, testPodNamespace, testPodInfraContaner),
		},
		Version: reqVersion,
	}
}

func ipVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "4"
	} else {
		return "6"
	}
}

type cmdAddDelTester struct {
	server   *cniserver.CNIServer
	ctx      context.Context
	testNS   ns.NetNS
	targetNS ns.NetNS
	request  *cnimsg.CniCmdRequestMessage
	vethName string
}

func (tester *cmdAddDelTester) setNS(testNS ns.NetNS, targetNS ns.NetNS) {
	tester.testNS = testNS
	tester.targetNS = targetNS
}

func (tester *cmdAddDelTester) cmdAddTest(tc testCase, dataDir string) (*current.Result, error) {
	// Generate network config and command arguments
	tester.request = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin
	var result *current.Result
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		response, err := tester.server.CmdAdd(tester.ctx, tester.request)
		Expect(err).NotTo(HaveOccurred())

		r, err := current.NewResult(response.CniResult)
		Expect(err).NotTo(HaveOccurred())

		result, err = current.GetResult(r)
		Expect(err).NotTo(HaveOccurred())

		Expect(len(result.Interfaces)).To(Equal(2))

		Expect(result.Interfaces[1].Name).To(Equal(IFNAME))
		Expect(result.Interfaces[1].Mac).To(HaveLen(17)) //mac is random
		Expect(result.Interfaces[1].Sandbox).To(Equal(tester.targetNS.Path()))

		// Check for the veth link in the main namespace
		hostIfaceName := agent.GenerateContainerInterfaceName(testPod, testPodNamespace)
		Expect(result.Interfaces[0].Name).To(Equal(hostIfaceName))
		Expect(result.Interfaces[0].Mac).To(HaveLen(17))

		link, err := netlink.LinkByName(result.Interfaces[0].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))
		Expect(link.Attrs().Name).To(Equal(hostIfaceName))
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(result.Interfaces[0].Mac))

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Find the veth peer in the container namespace and the default route
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()
		// Wait interface plugged on namespace
		linkList, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		Expect(2).To(Equal(len(linkList)))
		link, err := netlink.LinkByName(IFNAME)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(IFNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))

		expCIDRsV4, _ := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(addrs)).To(Equal(len(expCIDRsV4)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGatewayCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(Equal(true))
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	return result, nil
}

func buildOneConfig(name, cniVersion string, orig *Net, prevResult types.Result) (*Net, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	config := make(map[string]interface{})
	confBytes, err := json.Marshal(orig)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	for key, value := range inject {
		config[key] = value
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	conf := &Net{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("error parsing configuration: %s", err)
	}

	return conf, nil

}

func (tester *cmdAddDelTester) cmdCheckTest(tc testCase, conf *Net, dataDir string) {
	// Generate network config and command arguments
	tester.request = tc.createCheckCmdArgs(tester.targetNS, conf, dataDir)

	// Execute cmdCHECK on the plugin
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		_, err := tester.server.CmdCheck(tester.ctx, tester.request)
		Expect(err).NotTo(HaveOccurred())

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Find the veth peer in the container namespace and the default route
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(IFNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))

		expCIDRsV4, _ := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(addrs)).To(Equal(len(expCIDRsV4)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGatewayCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(Equal(true))
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func (tester *cmdAddDelTester) cmdDelTest(tc testCase, dataDir string) {
	tester.request = tc.createCmdArgs(tester.targetNS, dataDir)
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		_, err := tester.server.CmdDel(tester.ctx, tester.request)
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure the host veth has been deleted
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure the container veth has been deleted
	err = tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(tester.vethName)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func newTester() *cmdAddDelTester {
	tester := &cmdAddDelTester{}
	ifaceStore := agent.NewInterfaceStore()
	tester.server = cniserver.New(testSock, "", testNodeConfig, ovsServiceMock, ofServiceMock, ifaceStore)
	ctx, _ := context.WithCancel(context.Background())
	tester.ctx = ctx
	return tester
}

func cmdAddDelCheckTest(testNS ns.NetNS, tc testCase, dataDir string) {
	Expect(tc.cniVersion).To(Equal("0.4.0"))

	// Get a Add/Del tester based on test case version
	tester := newTester()

	targetNS, err := testutils.NewNS()
	Expect(err).NotTo(HaveOccurred())
	defer targetNS.Close()
	tester.setNS(testNS, targetNS)

	ipamResult := test.GenerateIPAMResult("0.4.0", tc.addresses, tc.routes, tc.dns)
	ipamMock.EXPECT().Add(mock.Any(), mock.Any()).Return(ipamResult, nil).AnyTimes()

	// Mock ovs output while get ovs port external configuration
	ovsPortname := agent.GenerateContainerInterfaceName(testPod, testPodNamespace)
	ovsPortUUID := uuid.New().String()
	ovsServiceMock.EXPECT().CreatePort(ovsPortname, ovsPortname, mock.Any()).Return(ovsPortUUID, nil).AnyTimes()
	ovsServiceMock.EXPECT().GetOFPort(ovsPortname).Return(int32(10), nil).AnyTimes()
	ofServiceMock.EXPECT().InstallPodFlows(ovsPortname, mock.Any(), mock.Any(), mock.Any(), mock.Any()).Return(nil)

	// Test ip allocation
	prevResult, err := tester.cmdAddTest(tc, dataDir)
	Expect(err).NotTo(HaveOccurred())

	Expect(prevResult).NotTo(BeNil())

	confString := tc.netConfJSON(dataDir)

	conf := &Net{}
	err = json.Unmarshal([]byte(confString), &conf)
	Expect(err).NotTo(HaveOccurred())

	conf.IPAM, _, err = allocator.LoadIPAMConfig([]byte(confString), "")
	Expect(err).NotTo(HaveOccurred())

	newConf, err := buildOneConfig("testConfig", tc.cniVersion, conf, prevResult)
	Expect(err).NotTo(HaveOccurred())

	// Test CHECK
	tester.cmdCheckTest(tc, newConf, dataDir)

	// Test delete
	ovsServiceMock.EXPECT().DeletePort(ovsPortUUID).Return(nil).AnyTimes()
	ofServiceMock.EXPECT().UninstallPodFlows(ovsPortname).Return(nil)
	tester.cmdDelTest(tc, dataDir)
}

func getContainerIPMacConfig(ipamResult *current.Result) (string, string) {
	containerMAC := ipamResult.Interfaces[1].Mac
	containerIP := ""
	for _, ipc := range ipamResult.IPs {
		if ipc.Version == "4" {
			containerIP = ipc.Address.IP.String()
			break
		}
	}
	return containerIP, containerMAC
}

var _ = Describe("CNI server operations", func() {
	var originalNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new netNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = ioutil.TempDir("", "okn_server_test")
		Expect(err).NotTo(HaveOccurred())

		ipamMock.EXPECT().Del(mock.Any(), mock.Any()).Return(nil).AnyTimes()
		ipamMock.EXPECT().Check(mock.Any(), mock.Any()).Return(nil).AnyTimes()

		ovsServiceMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).AnyTimes()
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
	})

	It("configures and deconfigures veth with default route with ADD/DEL/CHECK for 0.4.0 config", func() {
		testCases := []testCase{
			{
				// IPv4 only
				ranges: []rangeInfo{{
					subnet: "10.1.2.0/24",
				}},
				expGatewayCIDRs: []string{"10.1.2.1/24"},
				addresses:       []string{"10.1.2.100/24,10.1.2.1,4"},
				routes:          []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"},
			},
		}
		for _, tc := range testCases {
			tc.cniVersion = "0.4.0"
			cmdAddDelCheckTest(originalNS, tc, dataDir)
		}
	})
})

func TestOknServerFunc(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ipamMock = mocks.NewMockIPAMDriver(controller)
	_ = ipam.RegisterIPAMDriver("mock", ipamMock)
	ovsServiceMock = mocks.NewMockOVSdbClient(controller)
	ofServiceMock = mocks.NewMockOFClient(controller)
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI server operations suite")
}

func init() {
	nodeName := "node1"
	gwIP := net.ParseIP("192.168.1.1")
	gwMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	nodeGateway := &agent.Gateway{IP: gwIP, MAC: gwMAC, Name: "gw"}
	_, nodePodeCIDR, _ := net.ParseCIDR("192.168.1.0/24")

	testNodeConfig = &agent.NodeConfig{bridge, nodeName, nodePodeCIDR, nodeGateway}
}
