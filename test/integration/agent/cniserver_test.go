//go:build linux
// +build linux

// Copyright 2019 Antrea Authors
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

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	mock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sFake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	ipamtest "antrea.io/antrea/pkg/agent/cniserver/ipam/testing"
	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/metrics"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/util"
	cnimsg "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/wait"
)

const (
	IFName                = "eth0"
	ContainerID           = "dummy-0"
	testSock              = "/tmp/test.sock"
	testPod               = "test-1"
	testPodNamespace      = "t1"
	testPodInfraContainer = "test-111111"
	cniVersion            = "0.4.0"
)

const (
	netConfStr = `
	"cniVersion": "%s",
	"name": "testConfig",
	"type": "antrea"`

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

	chainCNIPrevResultTemplate = `{
  "cniVersion":"{{.CNIVersion}}",
  "interfaces":
   [
     {"name":"eth0"},
     {"name":"eth0"}
   ],
  "ips":
   [
     {
       "address":"{{.Subnet}}",
       "gateway":"{{.Gateway}}"}
   ],
  "routes":
   [
     {
       "dst":"{{ (index .Routes 0) }}",
       "gw":"{{.Gateway}}"
     }
   ],
   "dns":
   {
     "nameservers":
      [
        "{{.DNS}}"
      ]
   }
}`

	chainCNIConfStr = `{
"cniVersion":"%s",
"name":"azure",
"type":"antrea",
"prevResult":%s,
"ipam":{"type":"unknown"}
}`
)

var (
	ipamMock       *ipamtest.MockIPAMDriver
	ovsServiceMock *ovsconfigtest.MockOVSBridgeClient
	ofServiceMock  *openflowtest.MockClient
	routeMock      *routetest.MockInterface
)

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
	CNIVersion string // CNI Version
	Subnet     string // Single Subnet config: Subnet CIDR
	Gateway    string // Single Subnet config: Gateway
	Routes     []string
	DNS        []string

	t               *testing.T
	name            string
	ranges          []rangeInfo // Ranges list (multiple subnets config)
	expGatewayCIDRs []string    // Expected Gateway addresses in CIDR form
	addresses       []string
	networkConfig   string
	validateMetrics bool
}

func (tc testCase) netConfJSON(dataDir string) string {
	conf := fmt.Sprintf(netConfStr, tc.CNIVersion)
	conf += netDefault
	if tc.Subnet != "" || tc.ranges != nil {
		conf += ipamStartStr
		if dataDir != "" {
			conf += fmt.Sprintf(ipamDataDirStr, dataDir)
		}
		if tc.Subnet != "" {
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
	conf := fmt.Sprintf(subnetConfStr, tc.Subnet)
	if tc.Gateway != "" {
		conf += fmt.Sprintf(gatewayConfStr, tc.Gateway)
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
		require.Nil(tc.t, err)
		if ipVersion(ip) == "4" {
			cidrsV4 = append(cidrsV4, cidr)
		} else {
			cidrsV6 = append(cidrsV6, cidr)
		}
	}
	if tc.Subnet != "" {
		appendSubnet(tc.Subnet)
	}
	for _, r := range tc.ranges {
		appendSubnet(r.subnet)
	}
	return cidrsV4, cidrsV6
}

func (tc testCase) createCmdArgs(targetNS ns.NetNS, dataDir string) *cnimsg.CniCmdRequest {
	conf := tc.netConfJSON(dataDir)
	if len(tc.networkConfig) > 0 {
		conf = tc.networkConfig
	}
	return &cnimsg.CniCmdRequest{
		CniArgs: &cnimsg.CniCmdArgs{
			ContainerId:          ContainerID,
			Ifname:               IFName,
			Netns:                targetNS.Path(),
			NetworkConfiguration: []byte(conf),
			Args:                 cniservertest.GenerateCNIArgs(testPod, testPodNamespace, testPodInfraContainer),
		},
	}
}

func (tc testCase) createCheckCmdArgs(targetNS ns.NetNS, config *Net, dataDir string) *cnimsg.CniCmdRequest {
	conf, err := json.Marshal(config)
	require.Nil(tc.t, err)

	return &cnimsg.CniCmdRequest{
		CniArgs: &cnimsg.CniCmdArgs{
			ContainerId:          ContainerID,
			Ifname:               IFName,
			Netns:                targetNS.Path(),
			NetworkConfiguration: conf,
			Args:                 cniservertest.GenerateCNIArgs(testPod, testPodNamespace, testPodInfraContainer),
		},
	}
}

func ipVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}

type cmdAddDelTester struct {
	server                  *cniserver.CNIServer
	ctx                     context.Context
	testNS                  ns.NetNS
	targetNS                ns.NetNS
	request                 *cnimsg.CniCmdRequest
	vethName                string
	podNetworkWait          *wait.Group
	flowRestoreCompleteWait *wait.Group
}

func (tester *cmdAddDelTester) setNS(testNS ns.NetNS, targetNS ns.NetNS) {
	tester.testNS = testNS
	tester.targetNS = targetNS
}

func linkByName(netNS ns.NetNS, name string) (link netlink.Link, err error) {
	err = netNS.Do(func(ns.NetNS) error {
		link, err = netlink.LinkByName(name)
		return err
	})
	return link, err
}

func addrList(netNS ns.NetNS, link netlink.Link, family int) (addrs []netlink.Addr, err error) {
	err = netNS.Do(func(ns.NetNS) error {
		addrs, err = netlink.AddrList(link, family)
		return err
	})
	return addrs, err
}

func routeList(netNS ns.NetNS, link netlink.Link) (routes []netlink.Route, err error) {
	err = netNS.Do(func(ns.NetNS) error {
		routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		return err
	})
	return routes, err
}

func matchRoute(expectedCIDR string, routes []netlink.Route) (*netlink.Route, error) {
	gwIP, _, err := net.ParseCIDR(expectedCIDR)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		// For default route, `Dst` is 0.0.0.0/0 or ::/0, rather than nil.
		if route.Dst != nil && route.Dst.IP.IsUnspecified() && route.Src == nil && route.Gw.Equal(gwIP) {
			return &route, nil
		}
	}
	return nil, nil
}

// checkContainerNetworking checks for the presence of the interface called IFName inside the
// container namespace and checks for the presence of a default route through the Pod CIDR Gateway.
func (tester *cmdAddDelTester) checkContainerNetworking(tc testCase) {
	testRequire := require.New(tc.t)
	testAssert := assert.New(tc.t)

	link, err := linkByName(tester.targetNS, IFName)
	testRequire.Nil(err)
	testRequire.Equal(IFName, link.Attrs().Name)
	testRequire.IsType(&netlink.Veth{}, link)

	expCIDRsV4, _ := tc.expectedCIDRs()
	addrs, err := addrList(tester.targetNS, link, netlink.FAMILY_V4)
	testRequire.Nil(err)
	// make sure that the IP addresses were correctly assigned to the container's interface
	testRequire.Len(addrs, len(expCIDRsV4))
	for _, expAddr := range expCIDRsV4 {
		findAddr := func() bool {
			for _, addr := range addrs {
				if expAddr.Contains(addr.IP) {
					return true
				}
			}
			return false
		}
		found := findAddr()
		testAssert.Truef(found, "No IP address assigned from Subnet %v", expAddr)
	}

	// Check that default route exists.
	routes, err := routeList(tester.targetNS, link)
	testRequire.Nil(err)
	for _, cidr := range tc.expGatewayCIDRs {
		expectedRoute, err := matchRoute(cidr, routes)
		testRequire.Nil(err)
		testRequire.NotNil(expectedRoute)
	}
}

func (tester *cmdAddDelTester) cmdAddTest(tc testCase, dataDir string) (*current.Result, error) {
	testRequire := require.New(tc.t)
	var err error

	// Generate network config and command arguments.
	tester.request = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin.
	var response *cnimsg.CniCmdResponse
	err = tester.testNS.Do(func(ns.NetNS) error {
		response, err = tester.server.CmdAdd(tester.ctx, tester.request)
		return err
	})
	testRequire.Nil(err)

	result := &current.Result{}
	err = json.Unmarshal(response.CniResult, result)
	testRequire.Nil(err)

	testRequire.Len(result.Interfaces, 2)

	testRequire.Equal(IFName, result.Interfaces[1].Name)
	testRequire.Len(result.Interfaces[1].Mac, 17) // mac is random
	testRequire.Equal(tester.targetNS.Path(), result.Interfaces[1].Sandbox)

	// Check for the veth link in the test namespace.
	hostIfaceName := util.GenerateContainerInterfaceName(testPod, testPodNamespace, ContainerID)
	testRequire.Equal(hostIfaceName, result.Interfaces[0].Name)
	testRequire.Len(result.Interfaces[0].Mac, 17)

	link, err := linkByName(tester.testNS, result.Interfaces[0].Name)
	testRequire.Nil(err)
	tester.vethName = result.Interfaces[0].Name

	testRequire.IsType(&netlink.Veth{}, link)
	testRequire.Equal(hostIfaceName, link.Attrs().Name)
	testRequire.Equal(result.Interfaces[0].Mac, link.Attrs().HardwareAddr.String())

	var linkList []netlink.Link
	err = tester.targetNS.Do(func(ns.NetNS) error {
		linkList, err = netlink.LinkList()
		return err
	})
	testRequire.Nil(err)
	// when running the integration tests in a Docker image on macOS (Docker
	// Desktop), we observe that the namespace includes 4 links, not 2
	// (localhost and veth). It seems that the HyperKit Linux VM loads the
	// ipip module, which means that the Linux Kernel creates 2 extra
	// interfaces in each namespace (tunl0 and ip6tnl).
	testRequire.GreaterOrEqual(len(linkList), 2)
	// check that the list includes the eth0 veth
	vethFound := false
	for _, link := range linkList {
		if link.Type() == "veth" && link.Attrs().Name == IFName {
			vethFound = true
			break
		}
	}
	testRequire.Truef(vethFound, "Missing '%s' veth in target namespace", IFName)

	// Find the veth peer in the container namespace and the default route.
	tester.checkContainerNetworking(tc)

	return result, nil
}

func buildOneConfig(name, cniVersion string, orig *Net, prevResult types.Result) (*Net, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"CNIVersion": cniVersion,
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
	testRequire := require.New(tc.t)
	var err error

	// Generate network config and command arguments.
	tester.request = tc.createCheckCmdArgs(tester.targetNS, conf, dataDir)

	// Execute cmdCHECK on the plugin.
	err = tester.testNS.Do(func(ns.NetNS) error {
		_, err = tester.server.CmdCheck(tester.ctx, tester.request)
		return err
	})
	testRequire.Nil(err)

	// Find the veth peer in the container namespace and the default route.
	tester.checkContainerNetworking(tc)

	// If validateMetrics flag is set, check pod count metrics.
	if tc.validateMetrics {
		expectedStr := `
		# HELP antrea_agent_local_pod_count [STABLE] Number of Pods on local Node which are managed by the Antrea Agent.
		# TYPE antrea_agent_local_pod_count gauge
		antrea_agent_local_pod_count 1
		`
		assert.Equal(tc.t, nil, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedStr), "antrea_agent_local_pod_count"))
	}

}

func (tester *cmdAddDelTester) cmdDelTest(tc testCase, dataDir string) {
	testRequire := require.New(tc.t)
	var err error

	tester.request = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdDEL on the plugin.
	err = tester.testNS.Do(func(ns.NetNS) error {
		resp, err := tester.server.CmdDel(tester.ctx, tester.request)
		if err != nil {
			return err
		}
		if resp.Error != nil {
			return &types.Error{
				Code: uint(resp.Error.Code),
				Msg:  resp.Error.Message,
			}
		}
		return nil
	})
	testRequire.Nil(err)

	var link netlink.Link

	// Make sure the container veth has been deleted
	link, err = linkByName(tester.targetNS, IFName)
	testRequire.NotNil(err)
	testRequire.Nil(link)

	// Make sure the host veth has been deleted.
	link, err = linkByName(tester.testNS, tester.vethName)
	testRequire.NotNil(err)
	testRequire.Nil(link)

	// If validateMetrics flag is set, check Pod count metrics.
	if tc.validateMetrics {
		expectedStr := `
		# HELP antrea_agent_local_pod_count [STABLE] Number of Pods on local Node which are managed by the Antrea Agent.
		# TYPE antrea_agent_local_pod_count gauge
		antrea_agent_local_pod_count 0
		`
		assert.Equal(tc.t, nil, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedStr), "antrea_agent_local_pod_count"))
	}
}

func newTester() *cmdAddDelTester {
	tester := &cmdAddDelTester{}
	ifaceStore := interfacestore.NewInterfaceStore()
	tester.podNetworkWait = wait.NewGroup()
	tester.flowRestoreCompleteWait = wait.NewGroup()
	tester.server = cniserver.New(testSock,
		"",
		getTestNodeConfig(false),
		nil,
		k8sFake.NewSimpleClientset(),
		routeMock,
		false, false, false, false, &config.NetworkConfig{InterfaceMTU: 1450},
		tester.podNetworkWait.Increment(),
		tester.flowRestoreCompleteWait,
		nil,
	)
	tester.server.Initialize(ovsServiceMock, ofServiceMock, ifaceStore, channel.NewSubscribableChannel("PodUpdate", 100))
	ctx := context.Background()
	tester.ctx = ctx
	return tester
}

func cmdAddDelCheckTest(testNS ns.NetNS, tc testCase, dataDir string) {
	testRequire := require.New(tc.t)
	testAssert := assert.New(tc.t)

	testRequire.Equal(cniVersion, tc.CNIVersion)

	// Get a Add/Del tester based on test case version
	tester := newTester()

	targetNS, err := testutils.NewNS()
	testRequire.Nil(err)
	targetNSClosed := false
	defer func() {
		if !targetNSClosed {
			targetNS.Close()
			testutils.UnmountNS(targetNS)
		}
	}()
	tester.setNS(testNS, targetNS)

	ipamResult := &ipam.IPAMResult{Result: *ipamtest.GenerateIPAMResult(tc.addresses, tc.Routes, tc.DNS)}
	ipamMock.EXPECT().Add(mock.Any(), mock.Any(), mock.Any()).Return(true, ipamResult, nil).AnyTimes()

	// Mock ovs output while get ovs port external configuration
	ovsPortname := util.GenerateContainerInterfaceName(testPod, testPodNamespace, ContainerID)
	ovsPortUUID := uuid.New().String()
	ovsServiceMock.EXPECT().CreatePort(ovsPortname, ovsPortname, mock.Any()).Return(ovsPortUUID, nil).AnyTimes()
	ovsServiceMock.EXPECT().GetOFPort(ovsPortname, false).Return(int32(10), nil).AnyTimes()
	ofServiceMock.EXPECT().InstallPodFlows(ovsPortname, mock.Any(), mock.Any(), mock.Any(), uint16(0), nil).Return(nil)

	tester.podNetworkWait.Done()

	testAssert.NoError(tester.flowRestoreCompleteWait.WaitWithTimeout(1 * time.Second))

	// Test ips allocation
	prevResult, err := tester.cmdAddTest(tc, dataDir)
	testRequire.Nil(err)

	testRequire.NotNil(prevResult)

	confString := tc.netConfJSON(dataDir)

	conf := &Net{}
	err = json.Unmarshal([]byte(confString), &conf)
	testRequire.Nil(err)

	conf.IPAM, _, err = allocator.LoadIPAMConfig([]byte(confString), "")
	testRequire.Nil(err)

	newConf, err := buildOneConfig("testConfig", tc.CNIVersion, conf, prevResult)
	testRequire.Nil(err)

	// Test CHECK
	tester.cmdCheckTest(tc, newConf, dataDir)

	// Test delete
	ovsServiceMock.EXPECT().DeletePort(ovsPortUUID).Return(nil).AnyTimes()
	ofServiceMock.EXPECT().UninstallPodFlows(ovsPortname).Return(nil)
	tester.cmdDelTest(tc, dataDir)

	// DEL must complete without error when called multiple times.
	tester.cmdDelTest(tc, dataDir)

	// DEL must complete without error when netns is missing.
	targetNS.Close()
	testutils.UnmountNS(targetNS)
	targetNSClosed = true
	tester.cmdDelTest(tc, dataDir)
}

func TestAntreaServerFunc(t *testing.T) {
	controller := mock.NewController(t)
	ipamMock = ipamtest.NewMockIPAMDriver(controller)
	ipam.RegisterIPAMDriver("mock", ipamMock)
	ovsServiceMock = ovsconfigtest.NewMockOVSBridgeClient(controller)
	ofServiceMock = openflowtest.NewMockClient(controller)
	routeMock = routetest.NewMockInterface(controller)

	var originalNS ns.NetNS
	var dataDir string

	setup := func() {
		// Create a new netNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		require.Nil(t, err)

		dataDir, err = os.MkdirTemp("", "antrea_server_test")
		require.Nil(t, err)

		ipamMock.EXPECT().Del(mock.Any(), mock.Any(), mock.Any()).Return(true, nil).AnyTimes()
		ipamMock.EXPECT().Check(mock.Any(), mock.Any(), mock.Any()).Return(true, nil).AnyTimes()

		ovsServiceMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).AnyTimes()
		ovsServiceMock.EXPECT().IsHardwareOffloadEnabled().Return(false).AnyTimes()
		ovsServiceMock.EXPECT().GetOVSDatapathType().Return(ovsconfig.OVSDatapathSystem).AnyTimes()

		routeMock.EXPECT().AddLocalAntreaFlexibleIPAMPodRule([]net.IP{net.ParseIP("10.1.2.100")}).Return(nil).Times(1)
		routeMock.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule([]net.IP{net.ParseIP("10.1.2.100")}).Return(nil).Times(1)
	}

	teardown := func() {
		assert.Nil(t, os.RemoveAll(dataDir))
		assert.Nil(t, originalNS.Close())
		assert.Nil(t, testutils.UnmountNS(originalNS))
	}

	testCases := []testCase{
		{
			name:       fmt.Sprintf("ADD/DEL/CHECK for %s config", cniVersion),
			CNIVersion: cniVersion,
			// IPv4 only
			ranges: []rangeInfo{{
				subnet: "10.1.2.0/24",
			}},
			expGatewayCIDRs: []string{"10.1.2.1/24"},
			addresses:       []string{"10.1.2.100/24,10.1.2.1,4"},
			Routes:          []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"},
		},
		{
			name:       fmt.Sprintf("Prometheus metrics test with ADD/DEL/CHECK for %s config", cniVersion),
			CNIVersion: cniVersion,
			// IPv4 only
			ranges: []rangeInfo{{
				subnet: "10.1.2.0/24",
			}},
			expGatewayCIDRs: []string{"10.1.2.1/24"},
			addresses:       []string{"10.1.2.100/24,10.1.2.1,4"},
			Routes:          []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"},
			validateMetrics: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.name, "Prometheus") {
				// Initialize Pod metrics
				metrics.InitializePodMetrics()
			}
			setup()
			defer teardown()
			tc.t = t
			cmdAddDelCheckTest(originalNS, tc, dataDir)
		})
	}
}

func setupChainTest(
	testNodeConfig *config.NodeConfig, controller *mock.Controller, inServer *cniserver.CNIServer, netNS ns.NetNS, newServer bool,
) (server *cniserver.CNIServer, hostVeth, containerVeth net.Interface, err error) {
	if newServer {
		routeMock = routetest.NewMockInterface(controller)
		podNetworkWait := wait.NewGroup()
		flowRestoreCompleteWait := wait.NewGroup()
		server = cniserver.New(testSock,
			"",
			testNodeConfig,
			nil,
			k8sFake.NewSimpleClientset(),
			routeMock,
			true, false, false, false, &config.NetworkConfig{InterfaceMTU: 1450},
			podNetworkWait, flowRestoreCompleteWait, nil)
	} else {
		server = inServer
	}

	err = netNS.Do(func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err = ip.SetupVethWithName(IFName, "", 1500, "", hostNS)
		return err
	})
	if err != nil {
		return
	}

	_, dst, _ := net.ParseCIDR("10.10.10.1/32")
	route := &netlink.Route{
		LinkIndex: hostVeth.Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
	}
	err = netlink.RouteReplace(route)
	return

}

func TestCNIServerChaining(t *testing.T) {
	if _, inContainer := os.LookupEnv("INCONTAINER"); !inContainer {
		t.Skipf("Skip test runs only in container")
	}

	testNodeConfig := getTestNodeConfig(false)
	testRequire := require.New(t)
	controller := mock.NewController(t)
	var server *cniserver.CNIServer
	testContainerOFPort := int32(1234)
	testPatchPortName := "antrea-gw0"
	ctx := context.Background()

	tc := testCase{
		name:       "CNI chaining ",
		CNIVersion: cniVersion,
		Subnet:     "10.10.10.2/24",
		Gateway:    "10.10.10.1",
		Routes:     []string{"10.0.0.0/8"},
		DNS:        []string{"8.8.8.8"},
	}

	newServer := true
	for i := 0; i < 2; i++ {
		netNS, err := testutils.NewNS()
		testRequire.Nil(err)

		var hostVeth net.Interface
		server, hostVeth, _, err = setupChainTest(testNodeConfig, controller, server, netNS, newServer)
		testRequire.Nil(err)
		if newServer {
			ovsServiceMock = ovsconfigtest.NewMockOVSBridgeClient(controller)
			ofServiceMock = openflowtest.NewMockClient(controller)
			ifaceStore := interfacestore.NewInterfaceStore()
			ovsServiceMock.EXPECT().IsHardwareOffloadEnabled().Return(false).AnyTimes()
			ovsServiceMock.EXPECT().GetOVSDatapathType().Return(ovsconfig.OVSDatapathSystem).AnyTimes()
			err = server.Initialize(ovsServiceMock, ofServiceMock, ifaceStore, channel.NewSubscribableChannel("PodUpdate", 100))
			testRequire.Nil(err)
		}

		// create request
		prevResultParser := template.Must(template.New("").Parse(chainCNIPrevResultTemplate))
		prevResult := bytes.NewBuffer(nil)
		if err := prevResultParser.Execute(prevResult, tc); err != nil {
			t.Errorf("parse template failed: %v", err)
		}
		tc.networkConfig = fmt.Sprintf(chainCNIConfStr, tc.CNIVersion, prevResult.String())
		cniReq := tc.createCmdArgs(netNS, "")

		// test cmdAdd
		ovsPortname := hostVeth.Name
		ovsPortUUID := uuid.New().String()
		podIP, _, err := net.ParseCIDR(tc.Subnet)
		testRequire.Nil(err)
		containerIntf, err := util.GetNSDevInterface(netNS.Path(), IFName)
		testRequire.Nil(err)

		orderedCalls := make([]any, 0)
		testNodeConfig.GatewayConfig.Name = testPatchPortName

		// Pod port expectations
		orderedCalls = append(orderedCalls,
			routeMock.EXPECT().MigrateRoutesToGw(hostVeth.Name),
			ovsServiceMock.EXPECT().CreatePort(ovsPortname, ovsPortname, mock.Any()).Return(ovsPortUUID, nil),
			ovsServiceMock.EXPECT().GetOFPort(ovsPortname, false).Return(testContainerOFPort, nil),
			ofServiceMock.EXPECT().InstallPodFlows(ovsPortname, []net.IP{podIP}, containerIntf.HardwareAddr, mock.Any(), uint16(0), nil),
		)
		mock.InOrder(orderedCalls...)
		cniResp, err := server.CmdAdd(ctx, cniReq)
		testRequire.Nil(err)
		// in chaining mode, we do not modify the result
		testRequire.JSONEq(prevResult.String(), string(cniResp.CniResult))

		// test cmdDel
		containterHostRt := util.NewIPNet(podIP)
		orderedCalls = nil
		orderedCalls = append(orderedCalls,
			routeMock.EXPECT().UnMigrateRoutesFromGw(containterHostRt, ""),
			ofServiceMock.EXPECT().UninstallPodFlows(ovsPortname),
			ovsServiceMock.EXPECT().DeletePort(ovsPortUUID),
		)
		mock.InOrder(orderedCalls...)
		cniResp, err = server.CmdDel(ctx, cniReq)
		testRequire.Nil(err)
		testRequire.Equal([]byte{}, cniResp.CniResult)

		_ = netNS.Close()
		tmpLink, _ := netlink.LinkByName(hostVeth.Name)
		_ = netlink.LinkDel(tmpLink)
		newServer = false
	}
}

func TestCNIServerGCForHostLocalIPAM(t *testing.T) {
	// Running in a container is required as we modify /var/lib/cni/networks.
	if _, inContainer := os.LookupEnv("INCONTAINER"); !inContainer {
		t.Skipf("Skip test runs only in container")
	}

	testNodeConfig := getTestNodeConfig(true)

	usedIPv4 := net.ParseIP("10.0.0.1")
	usedIPv6 := net.ParseIP("2001:db8:a::1")
	unusedIPv4 := net.ParseIP("10.0.0.2")
	unusedIPv6 := net.ParseIP("2001:db8:a::2")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: testNodeConfig.Name,
		},
		Status: corev1.PodStatus{
			PodIP: usedIPv4.String(),
			PodIPs: []corev1.PodIP{
				{IP: usedIPv4.String()},
				{IP: usedIPv6.String()},
			},
		},
	}

	// we need to use the default data dir, as it is hardcoded in the Antrea logic
	const ipamDataDir = "/var/lib/cni/networks"
	// make sure we start from a clean state, this will not interfere with any other test
	require.NoError(t, os.RemoveAll(ipamDataDir))
	// clean up directory at the end of the test
	defer os.RemoveAll(ipamDataDir)

	// reserve all 4 IPs using host-local IPAM
	const rangeID = "0"
	reserveIPs := func(cID string, ips ...net.IP) {
		ipamStore, err := disk.New("antrea", ipamDataDir)
		require.NoError(t, err)
		defer ipamStore.Close()
		ipamStore.Lock()
		defer ipamStore.Unlock()
		for _, ip := range ips {
			reserved, err := ipamStore.Reserve(cID, IFName, ip, rangeID)
			require.NoError(t, err)
			require.True(t, reserved) // should not have been previously reserved
		}
	}
	reserveIPs("c0", usedIPv4, usedIPv6)
	reserveIPs("c1", unusedIPv4, unusedIPv6)

	// create mocks and test CNIServer
	controller := mock.NewController(t)
	ovsServiceMock := ovsconfigtest.NewMockOVSBridgeClient(controller)
	ovsServiceMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).AnyTimes()
	ovsServiceMock.EXPECT().IsHardwareOffloadEnabled().Return(false).AnyTimes()
	ovsServiceMock.EXPECT().GetOVSDatapathType().Return(ovsconfig.OVSDatapathSystem).AnyTimes()
	ofServiceMock := openflowtest.NewMockClient(controller)
	routeMock := routetest.NewMockInterface(controller)
	ifaceStore := interfacestore.NewInterfaceStore()
	podNetworkWait := wait.NewGroup()
	flowRestoreCompleteWait := wait.NewGroup()
	k8sClient := k8sFake.NewSimpleClientset(pod)
	server := cniserver.New(
		testSock,
		"",
		testNodeConfig,
		nil,
		k8sClient,
		routeMock,
		false, false, false, false, &config.NetworkConfig{InterfaceMTU: 1450},
		podNetworkWait, flowRestoreCompleteWait, nil,
	)

	// call Initialize, which will run reconciliation and perform host-local IPAM garbage collection
	server.Initialize(ovsServiceMock, ofServiceMock, ifaceStore, channel.NewSubscribableChannel("PodUpdate", 100))

	getIPs := func(cID string) []net.IP {
		ipamStore, err := disk.New("antrea", "")
		require.NoError(t, err)
		defer ipamStore.Close()
		ipamStore.Lock()
		defer ipamStore.Unlock()
		return ipamStore.GetByID(cID, IFName)
	}
	assert.ElementsMatch(t, getIPs("c0"), []net.IP{usedIPv4, usedIPv6})
	assert.Empty(t, getIPs("c1"))
}

func getTestNodeConfig(dualStack bool) *config.NodeConfig {
	nodeName := "node1"
	gwIPv4 := net.ParseIP("192.168.1.1")
	_, nodePodCIDRv4, _ := net.ParseCIDR("192.168.1.0/24")
	gwMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	gateway := &config.GatewayConfig{Name: "", IPv4: gwIPv4, MAC: gwMAC}
	nodeConfig := &config.NodeConfig{Name: nodeName, PodIPv4CIDR: nodePodCIDRv4, GatewayConfig: gateway}
	if dualStack {
		gwIPv6 := net.ParseIP("fd74:ca9b:172:18::1")
		_, nodePodCIDRv6, _ := net.ParseCIDR("fd74:ca9b:172:18::/64")
		gateway.IPv6 = gwIPv6
		nodeConfig.PodIPv6CIDR = nodePodCIDRv6
	}
	return nodeConfig
}
