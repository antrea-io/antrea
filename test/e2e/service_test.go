// Copyright 2020 Antrea Authors
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
	"bytes"
	"fmt"
	"html/template"
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/test/e2e/templates"
	"github.com/vmware-tanzu/antrea/test/e2e/util"
)

type serviceInfo struct {
	clientPods    []string
	serviceIP     string
	servicePort   int32
	nodeIP        []string
	nodePort      int32
	podIP         []string
	targetPort    int32
	clientCmd     string
	clientNodeCmd string
	serviceName   string
	clientName    string
}

func (s *serviceInfo) String() string {
	return fmt.Sprintf("\nclientPods:%s\nserviceIP:%s\nservicePort:%d\nnodeIP:%s\nnodePort:%d\npodIP;%s\ntargetPort:%d\nnodeCurlCmd:%s\n",
		s.clientPods, s.serviceIP, s.servicePort, s.nodeIP, s.nodePort, s.podIP, s.targetPort, s.clientCmd)
}

func setupService(data *TestData) (*serviceInfo, error) {
	info := &serviceInfo{serviceName: "httpbin", clientName: "curl", clientCmd: "curl", clientNodeCmd: "curl"}

	kubeconfigPath, err := provider.GetKubeconfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig, %v", err)
	}
	// Test requires kubectl, curl on test machine
	// curl on worker node
	kubectl := util.NewKubeCtl(kubeconfigPath)
	if err := kubectl.IsPresent(); err != nil {
		return nil, err
	}

	curl := exec.Command("curl", "--version")
	if err = curl.Run(); err != nil {
		return nil, fmt.Errorf("curl not present on local machine, %v", err)
	}

	if _, _, _, err = provider.RunCommandOnNode(nodeName(0), "curl --version"); err != nil {
		if _, _, _, err := provider.RunCommandOnNode(
			nodeName(0), "docker run --rm --network host byrnedo/alpine-curl --version"); err != nil {
			return nil, fmt.Errorf("curl not present on worker node, %v", err)
		}
		info.clientNodeCmd = "docker run --rm --network host byrnedo/alpine-curl"
	}

	// install service: http and client curl
	temps := []struct {
		depName  string
		tempName string
	}{
		{info.serviceName, templates.HTTPBinYAMLTemplate},
		{info.clientName, templates.CurlYAMLTemplate},
	}
	for _, temp := range temps {
		param := templates.DeploymentParam{
			Name:      temp.depName,
			Namespace: testNamespace,
			Replicas:  clusterInfo.numNodes,
		}

		parser := template.Must(template.New("").Parse(temp.tempName))
		out := bytes.NewBuffer(nil)
		if err := parser.Execute(out, param); err != nil {
			return nil, fmt.Errorf("parse %s template failed, %v", temp.depName, err)
		}
		if err := kubectl.Apply(out.Bytes()); err != nil {
			return nil, fmt.Errorf("apply %s manifest failed, %v", temp.depName, err)
		}
	}

	// wait for all pods come up
	for _, temp := range temps {
		pods, err := data.GetPodsFromDeployment(testNamespace, temp.depName)
		if err != nil {
			return nil, fmt.Errorf("get deployment for %s failed, %v", temp.depName, err)
		}
		if strings.Contains(pods[0], info.clientName) {
			info.clientPods = pods
		}
	}

	// get service IP and ports
	service, err := data.clientset.CoreV1().Services(testNamespace).Get(info.serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get service %s failed, %v", info.serviceName, err)
	}
	info.serviceIP = service.Spec.ClusterIP
	if len(service.Spec.Ports) != 1 {
		return nil, fmt.Errorf("service misconfiguration, use only one port")
	}
	port := service.Spec.Ports[0]
	if port.Port == 0 || port.NodePort == 0 {
		return nil, fmt.Errorf("service misconfiguration, service port and target port required")
	}
	info.servicePort = port.Port
	info.nodePort = port.NodePort
	if port.TargetPort.IntValue() != 0 {
		info.targetPort = int32(port.TargetPort.IntValue())
	} else {
		info.targetPort = port.Port
	}
	for _, port := range service.Spec.Ports {
		if port.Port != 0 {
			info.servicePort = port.Port
		}
	}

	// get backend pod IP of service
	endpoints, err := data.clientset.CoreV1().Endpoints(testNamespace).List(metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", info.serviceName)})
	if err != nil {
		return nil, fmt.Errorf("get endpoint for %s failed, %v", info.serviceName, err)
	}
	if len(endpoints.Items) != 1 {
		return nil, fmt.Errorf("service misconfiguration, more than one ep with name %s", info.serviceName)
	}
	ep := endpoints.Items[0]
	for _, s := range ep.Subsets {
		if len(s.Addresses) == 0 {
			continue
		}
		for _, addr := range ep.Subsets[0].Addresses {
			info.podIP = append(info.podIP, addr.IP)
		}
		break
	}

	//get nodes IP
	nodes, err := data.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed, %v", err)
	}
	for _, n := range nodes.Items {
		for _, addr := range n.Status.Addresses {
			if addr.Type != v1.NodeInternalIP {
				continue
			}
			info.nodeIP = append(info.nodeIP, addr.Address)
			break
		}
	}
	return info, nil
}

// TestDeploy is a "no-op" test that simply performs setup and teardown.
func TestService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	info, err := setupService(data)
	if err != nil {
		t.Errorf("setup service failed, %v", err)
		return
	}
	t.Logf("service info %s", info)

	// some helper function and struct
	rand.Seed(time.Now().UnixNano())
	nextRand := func() int {
		return rand.Intn(clusterInfo.numNodes)
	}

	type addrPort struct {
		address string
		port    int32
	}

	targetExpand := func(addrs []string, port int32) []addrPort {
		var targetList []addrPort
		for _, addr := range addrs {
			targetList = append(targetList, addrPort{address: addr, port: port})
		}
		return targetList
	}

	localRunner := func() (string, func(string, []string) error) {
		return "local", func(_ string, cmd []string) error {
			return exec.Command(cmd[0], cmd[1:]...).Run()
		}
	}

	nodeRunner := func() (string, func(string, []string) error) {
		return "node", func(source string, cmd []string) error {
			cmdStr := strings.Join(cmd, " ")
			rc, _, _, err := provider.RunCommandOnNode(source, cmdStr)
			if rc != 0 {
				return fmt.Errorf("cmd failed with rc %d", rc)
			}
			return err
		}
	}

	podRunner := func() (string, func(string, []string) error) {
		return "pod", func(source string, cmd []string) error {
			_, _, err := data.runCommandFromPod(testNamespace, source, "", cmd)
			return err
		}
	}

	testcases := []struct {
		description string
		source      string     // client called on test machine, worker node or pod
		targets     []addrPort // service targets
		runner      func() (string, func(string, []string) error)
		repeats     int // repeated client calls to each target
	}{
		{
			description: "======= Test Node Port ======",
			source:      "",                                                                  // curl from test machine
			targets:     []addrPort{{address: info.nodeIP[nextRand()], port: info.nodePort}}, // to a worker node with node port
			runner:      localRunner,
			repeats:     len(info.podIP) * 2, // covers LB
		},
		{
			description: "======= Test Node To Service ======",
			source:      clusterInfo.nodes[nextRand()].name,                            // client called on a worker node
			targets:     []addrPort{{address: info.serviceIP, port: info.servicePort}}, // to service IP and port
			runner:      nodeRunner,
			repeats:     len(info.podIP) * 2, // covers LB
		},
		{
			description: "======= Test Node To Pod ======",
			source:      clusterInfo.nodes[nextRand()].name,        // client called on a worker node
			targets:     targetExpand(info.podIP, info.targetPort), // to pod IP
			runner:      nodeRunner,
			repeats:     1,
		},
		{
			description: "======= Test Pod To Pod ======",
			source:      info.clientPods[nextRand()],               // client called on a worker node
			targets:     targetExpand(info.podIP, info.targetPort), // to pod IP
			runner:      podRunner,
			repeats:     1,
		},
		{
			description: "======= Test Pod To Service ======",
			source:      info.clientPods[nextRand()],                                   // client called on a worker node
			targets:     []addrPort{{address: info.serviceIP, port: info.servicePort}}, // to service IP, would be nice to use serviceName. Sometimes test fails with serviceName
			runner:      podRunner,
			repeats:     len(info.podIP) * 2, // cover LB
		},
		{
			description: "======= Test Pod To External ======",
			source:      info.clientPods[nextRand()],                      // client called on a worker node
			targets:     []addrPort{{address: "www.yahoo.com", port: 80}}, // to external service
			runner:      podRunner,
			repeats:     1,
		},
	}

	for _, tc := range testcases {
		srcType, execute := tc.runner()
		clientCmd := info.clientCmd
		if srcType == "node" {
			clientCmd = info.clientNodeCmd
		}
		t.Logf("%s", tc.description)
		t.Logf("From %s %s to %v", srcType, tc.source, tc.targets)
		for i := 0; i < tc.repeats; i++ {
			for _, target := range tc.targets {
				cmd := []string{
					"timeout", "10", clientCmd, // timeout in 5 sec
					fmt.Sprintf("http://%s:%d/status/200", target.address, target.port),
				}
				t.Logf("From %s %s: %s", srcType, tc.source, strings.Join(cmd, " "))
				if err := execute(tc.source, cmd); err != nil {
					t.Fatalf("cmd failed: %v", err)
				}
			}
		}
	}
}
