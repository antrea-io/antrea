// Copyright 2024 Antrea Authors
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

package e2e

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/test/e2e/providers/exec"
)

const (
	remoteASN = int32(65000)

	localASN        = int32(64512)
	updatedLocalASN = int32(64513)

	bgpPeerPassword = "password"

	bgpPolicyName = "test-policy"
)

func getAllNodeIPs() []string {
	ips := make([]string, 0, clusterInfo.numNodes)
	for _, node := range clusterInfo.nodes {
		ips = append(ips, node.ipv4Addr)
	}
	return ips
}

type FRRRoute struct {
	Prefix   string
	Nexthops []string
}

func (f *FRRRoute) String() string {
	sort.Strings(f.Nexthops)
	return fmt.Sprintf("%s via %s", f.Prefix, strings.Join(f.Nexthops, ","))
}

func routesToStrings(routes []FRRRoute) []string {
	s := make([]string, 0, len(routes))
	for _, route := range routes {
		s = append(s, route.String())
	}
	return s
}

func TestBGPPolicy(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)
	skipIfExternalFRRNotSet(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Log("Configure the remote FRR router with BGP")
	rc, stdout, stderr, err := runVtyshCommands(generateVtyshCommandsForConfiguringBGP(remoteASN, localASN))
	defer runVtyshCommands(generateVtyshCommandsForClearingBGP(remoteASN))
	t.Log(stdout)
	t.Log(stderr)
	require.NoError(t, err)
	require.Equal(t, 0, rc)

	t.Log("Update the specific Secret storing the passwords of BGP peers")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kubeNamespace,
			Name:      types.BGPPolicySecretName,
		},
		Data: map[string][]byte{
			fmt.Sprintf("%s-%d", externalInfo.externalFRRIPv4, remoteASN): []byte(bgpPeerPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(kubeNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(kubeNamespace).Delete(context.TODO(), types.BGPPolicySecretName, metav1.DeleteOptions{})

	t.Log("Create a test agnhost Pod")
	podName, podIPs, cleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string, hostNetwork bool) error {
		args := []string{"netexec", "--http-port=8080"}
		ports := []corev1.ContainerPort{
			{
				Name:          "http",
				ContainerPort: 8080,
				Protocol:      corev1.ProtocolTCP,
			},
		}
		return NewPodBuilder(name, ns, agnhostImage).
			OnNode(nodeName).
			WithArgs(args).
			WithPorts(ports).
			WithHostNetwork(hostNetwork).
			Create(data)
	}, "agnhost-", nodeName(0), data.testNamespace, false)
	defer cleanupFunc()
	podIP := podIPs.IPv4.String()

	t.Log("Create a test Service")
	svcClusterIP, err := data.createAgnhostClusterIPService("agnhost-svc", false, ptr.To[corev1.IPFamily](corev1.IPv4Protocol))
	defer data.deleteService(svcClusterIP.Namespace, svcClusterIP.Name)
	require.NoError(t, err)
	require.NotEqual(t, "", svcClusterIP.Spec.ClusterIP, "ClusterIP should not be empty")
	clusterIP := svcClusterIP.Spec.ClusterIP

	t.Log("Create a test BGPPolicy selecting all Nodes as well as advertising ClusterIPs and Pod CIDRs")
	bgpPolicy := &crdv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPolicyName,
		},
		Spec: crdv1alpha1.BGPPolicySpec{
			NodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			LocalASN:   localASN,
			ListenPort: ptr.To[int32](179),
			Advertisements: crdv1alpha1.Advertisements{
				Service: &crdv1alpha1.ServiceAdvertisement{
					IPTypes: []crdv1alpha1.ServiceIPType{crdv1alpha1.ServiceIPTypeClusterIP},
				},
				Pod: &crdv1alpha1.PodAdvertisement{},
			},
			BGPPeers: []crdv1alpha1.BGPPeer{
				{Address: externalInfo.externalFRRIPv4, ASN: remoteASN},
			},
		},
	}
	bgpPolicy, err = data.crdClient.CrdV1alpha1().BGPPolicies().Create(context.TODO(), bgpPolicy, metav1.CreateOptions{})
	defer data.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), bgpPolicyName, metav1.DeleteOptions{})
	require.NoError(t, err)

	t.Log("Get the routes installed on remote FRR router and verify them")
	expectedRoutes := make([]FRRRoute, 0)
	for _, node := range clusterInfo.nodes {
		expectedRoutes = append(expectedRoutes, FRRRoute{Prefix: node.podV4NetworkCIDR, Nexthops: []string{node.ipv4Addr}})
	}
	expectedRoutes = append(expectedRoutes, FRRRoute{Prefix: clusterIP + "/32", Nexthops: getAllNodeIPs()})
	checkFRRRouterBGPRoutes(t, routesToStrings(expectedRoutes), nil)

	t.Log("Verify the connectivity of the installed routes on remote FRR route")
	ipsToConnect := []string{podIP, clusterIP}
	for _, ip := range ipsToConnect {
		cmd := fmt.Sprintf("/usr/bin/wget -O - http://%s:8080/hostname -T 5", ip)
		rc, stdout, _, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, "")
		require.NoError(t, err)
		require.Equal(t, 0, rc)
		require.Equal(t, podName, stdout)
	}

	t.Log("Update the BGP configuration on the remote FRR router")
	rc, stdout, stderr, err = runVtyshCommands(generateVtyshCommandsForConfiguringBGP(remoteASN, updatedLocalASN))
	t.Log(stdout)
	t.Log(stderr)
	require.NoError(t, err)
	require.Equal(t, 0, rc)

	_, err = data.updateServiceInternalTrafficPolicy("agnhost-svc", true)
	require.NoError(t, err)

	t.Log("Update the test BGPPolicy with a new local ASN")
	updatedBGPPolicy := bgpPolicy.DeepCopy()
	updatedBGPPolicy.Spec.LocalASN = updatedLocalASN
	updatedBGPPolicy.Spec.Advertisements.Pod = nil
	_, err = data.crdClient.CrdV1alpha1().BGPPolicies().Update(context.TODO(), updatedBGPPolicy, metav1.UpdateOptions{})
	require.NoError(t, err)

	t.Log("Get routes installed on remote FRR router and verify them")
	expectedRoutes = []FRRRoute{{Prefix: clusterIP + "/32", Nexthops: []string{nodeIPv4(0)}}}
	notExpectedRoutes := []FRRRoute{{Prefix: clusterIP + "/32", Nexthops: getAllNodeIPs()}}
	checkFRRRouterBGPRoutes(t, routesToStrings(expectedRoutes), routesToStrings(notExpectedRoutes))

	t.Log("verify the connectivity of the installed routes on remote FRR route")
	ipsToConnect = []string{clusterIP}
	for _, ip := range ipsToConnect {
		cmd := fmt.Sprintf("/usr/bin/wget -O - http://%s:8080/hostname -T 5", ip)
		rc, stdout, _, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, "")
		require.NoError(t, err)
		require.Equal(t, 0, rc)
		require.Equal(t, podName, stdout)
	}
}

func checkFRRRouterBGPRoutes(t *testing.T, expectedRouteStrings, notExpectedRouteStrings []string) {
	t.Helper()
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		gotRoutes, err := dumpFRRRouterBGPRoutes()
		if err != nil {
			return false, err
		}
		gotRouteStrings := routesToStrings(gotRoutes)
		gotRoutesSet := sets.NewString(gotRouteStrings...)
		notExpectedRoutesSet := sets.NewString(notExpectedRouteStrings...)
		expectedRoutesSet := sets.NewString(expectedRouteStrings...)
		if !gotRoutesSet.IsSuperset(expectedRoutesSet) {
			return false, nil
		}
		if notExpectedRoutesSet.Len() != 0 && gotRoutesSet.IsSuperset(notExpectedRoutesSet) {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to get the expected BGP routes: %v", err)
	}
}

func runVtyshCommands(commands []string) (int, string, string, error) {
	return exec.RunDockerExecCommand(externalInfo.externalFRRCID, "/usr/bin/vtysh", "/", nil, strings.Join(commands, "\n"))
}

func generateVtyshCommandsForConfiguringBGP(localASN, remoteASN int32) []string {
	commands := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", localASN),
		"no bgp ebgp-requires-policy",
		"no bgp network import-check",
	}
	for _, node := range clusterInfo.nodes {
		commands = append(commands, fmt.Sprintf("neighbor %s remote-as %d", node.ipv4Addr, remoteASN))
		commands = append(commands, fmt.Sprintf("neighbor %s password %s", node.ipv4Addr, bgpPeerPassword))
	}
	commands = append(commands,
		"exit",
		"exit",
		"write memory")
	return commands
}

func generateVtyshCommandsForClearingBGP(localASN int32) []string {
	return []string{
		"configure terminal",
		fmt.Sprintf("no router bgp %d", localASN),
		"exit",
		"write memory",
	}
}

func dumpFRRRouterBGPRoutes() ([]FRRRoute, error) {
	rc, stdout, stderr, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, "/usr/bin/vtysh", "/", nil, "show ip route bgp")
	log.Println(stdout)
	log.Println(stderr)
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("error when running command to show BGP route")
	}

	routePattern := regexp.MustCompile(`B>\* ([\d\.\/]+) \[.*?\] via ([\d\.]+),`)
	nexthopPattern := regexp.MustCompile(`\* +via ([\d\.]+),`)
	var routes []FRRRoute
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		routeMatches := routePattern.FindStringSubmatch(line)
		if routeMatches != nil {
			route := FRRRoute{
				Prefix:   routeMatches[1],
				Nexthops: []string{routeMatches[2]},
			}
			routes = append(routes, route)
			continue
		}

		nexthopMatches := nexthopPattern.FindStringSubmatch(line)
		if nexthopMatches != nil && len(routes) > 0 {
			last := len(routes) - 1
			routes[last].Nexthops = append(routes[last].Nexthops, nexthopMatches[1])
		}
	}
	return routes, nil
}
