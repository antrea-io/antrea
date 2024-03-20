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
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/test/e2e/utils"
)

var ErrPodNotFound = errors.New("pod not found")

type KubernetesUtils struct {
	*TestData
	podCache map[string][]v1.Pod
	podLock  sync.Mutex
}

func NewKubernetesUtils(data *TestData) (*KubernetesUtils, error) {
	return &KubernetesUtils{
		TestData: data,
		podCache: map[string][]v1.Pod{},
	}, nil
}

// TestCase is a collection of TestSteps to be tested against.
type TestCase struct {
	Name  string
	Steps []*TestStep
}

// TestStep is a single unit of testing spec. It includes the policy specs that need to be
// applied for this test, the port to test traffic on and the expected Reachability matrix.
type TestStep struct {
	Name           string
	Reachability   *Reachability
	TestResources  []metav1.Object
	Ports          []int32
	Protocol       utils.AntreaPolicyProtocol
	Duration       time.Duration
	CustomProbes   []*CustomProbe
	CustomSetup    func()
	CustomTeardown func()
}

// CustomProbe will spin up (or update) SourcePod and DestPod such that Add event of Pods
// can be tested against expected connectivity among those Pods.
type CustomProbe struct {
	// Create or update a source Pod.
	SourcePod CustomPod
	// Create or update a destination Pod.
	DestPod CustomPod
	// Port on which the probe will be made.
	Port int32
	// Set the expected connectivity.
	ExpectConnectivity PodConnectivityMark
}

type probeResult struct {
	podFrom      Pod
	podTo        Pod
	connectivity PodConnectivityMark
	err          error
}

// TestNamespaceMeta holds the relevant metadata of a test Namespace during initialization.
type TestNamespaceMeta struct {
	Name   string
	Labels map[string]string
}

// GetPodByLabel returns a Pod with the matching Namespace and "pod" label if it's found.
// If the pod is not found, GetPodByLabel returns "ErrPodNotFound".
func (k *KubernetesUtils) GetPodByLabel(ns string, name string) (*v1.Pod, error) {
	pods, err := k.getPodsUncached(ns, "pod", name)
	if err != nil {
		return nil, fmt.Errorf("unable to get Pod in Namespace %s with label pod=%s: %w", ns, name, err)
	}
	if len(pods) == 0 {
		return nil, ErrPodNotFound
	}
	return &pods[0], nil
}

func (k *KubernetesUtils) getPodsUncached(ns string, key, val string) ([]v1.Pod, error) {
	v1PodList, err := k.clientset.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%v=%v", key, val),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list pods: %w", err)
	}
	return v1PodList.Items, nil
}

// GetPodsByLabel returns an array of all Pods in the given Namespace having a k/v label pair.
func (k *KubernetesUtils) GetPodsByLabel(ns string, key string, val string) ([]v1.Pod, error) {
	k.podLock.Lock()
	defer k.podLock.Unlock()
	if p, ok := k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)]; ok {
		return p, nil
	}

	v1PodList, err := k.getPodsUncached(ns, key, val)
	if err != nil {
		return nil, fmt.Errorf("unable to list pods: %w", err)
	}
	k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)] = v1PodList
	return v1PodList, nil
}

func (k *KubernetesUtils) LabelPod(ns, name, key, value string) (*v1.Pod, error) {
	pod, err := k.clientset.CoreV1().Pods(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	pod.Labels[key] = value
	return k.clientset.CoreV1().Pods(ns).Update(context.TODO(), pod, metav1.UpdateOptions{})
}

func (k *KubernetesUtils) getTCPv4SourcePortRangeFromPod(podNamespace, podNameLabel string) (int32, int32, error) {
	pod, err := k.GetPodByLabel(podNamespace, podNameLabel)
	if err != nil {
		return 0, 0, err
	}
	cmd := []string{
		"/bin/sh",
		"-c",
		"cat /proc/sys/net/ipv4/ip_local_port_range",
	}
	stdout, stderr, err := k.RunCommandFromPod(pod.Namespace, pod.Name, "c80", cmd)
	if err != nil || stderr != "" {
		log.Errorf("Failed to retrieve TCP source port range for Pod %s/%s", podNamespace, podNameLabel)
		return 0, 0, err
	}
	ports := strings.Fields(stdout)
	if len(ports) < 2 {
		log.Errorf("Failed to retrieve TCP source port range for Pod %s/%s", podNamespace, podNameLabel)
		return 0, 0, err
	}
	startPort, _ := strconv.ParseInt(ports[0], 0, 32)
	endPort, _ := strconv.ParseInt(ports[1], 0, 32)
	return int32(startPort), int32(endPort), nil
}

// ProbeCommand generates a command to probe the provider url.
// The executor parameter can be used to change where the prober will run. For example, it could be "ip netns exec NAME"
// to run the prober in another namespace.
// We try to connect 3 times. This dates back to when we were using the OVS netdev datapath for Kind clusters, as the
// first packet sent on a tunnel was always dropped (https://github.com/antrea-io/antrea/issues/467). We may be able to
// revisit this now that we use the OVS kernel datapath for Kind.
// "agnhost connect" outputs nothing when it succeeds. We output "CONNECTED" in such case and prepend a sequence
// number for each attempt, to make the result more informative. Example output:
// 1: CONNECTED
// 2: TIMEOUT
// 3: TIMEOUT
func ProbeCommand(url, protocol, executor string) []string {
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf(`for i in $(seq 1 3); do echo -n "${i}: " >&2 && %s /agnhost connect %s --timeout=1s --protocol=%s && echo "CONNECTED" >&2; done; echo "FINISHED" >&2`,
			executor, url, protocol),
	}
	return cmd
}

func (k *KubernetesUtils) probe(
	pod *v1.Pod,
	podName string,
	containerName string,
	dstAddr string,
	dstName string,
	port int32,
	protocol utils.AntreaPolicyProtocol,
	expectedResult *PodConnectivityMark,
) PodConnectivityMark {
	protocolStr := map[utils.AntreaPolicyProtocol]string{
		utils.ProtocolTCP:  "tcp",
		utils.ProtocolUDP:  "udp",
		utils.ProtocolSCTP: "sctp",
	}
	cmd := ProbeCommand(fmt.Sprintf("%s:%d", dstAddr, port), protocolStr[protocol], "")
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", pod.Name, containerName, pod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.RunCommandFromPod(pod.Namespace, pod.Name, containerName, cmd)
	// It needs to check both err and stderr because:
	// 1. The probe tried 3 times. If it checks err only, failure+failure+success would be considered connected.
	// 2. There might be an issue in Pod exec API that it sometimes doesn't return error when the probe fails. See #2394.
	var actualResult PodConnectivityMark
	if err != nil || stderr != "" {
		// If err != nil and stderr == "", then it means this probe failed because of
		// the command instead of connectivity. For example, container name doesn't exist.
		if stderr == "" {
			actualResult = Error
		}
		actualResult = DecideProbeResult(stderr, 3)
	} else {
		actualResult = Connected
	}
	if expectedResult != nil && *expectedResult != actualResult {
		log.Infof("%s -> %s: expected %s but got %s: err - %v /// stdout - %s /// stderr - %s", podName, dstName, *expectedResult, actualResult, err, stdout, stderr)
	}
	return actualResult
}

// DecideProbeResult uses the probe stderr to decide the connectivity.
func DecideProbeResult(stderr string, probeNum int) PodConnectivityMark {
	countConnected := strings.Count(stderr, "CONNECTED")
	countDropped := strings.Count(stderr, "TIMEOUT")
	// For our UDP rejection cases, agnhost will return:
	//   For IPv4: 'UNKNOWN: read udp [src]->[dst]: read: no route to host'
	//   For IPv6: 'UNKNOWN: read udp [src]->[dst]: read: permission denied'
	// To avoid incorrect identification, we use 'no route to host' and
	// `permission denied`, instead of 'UNKNOWN' as key string.
	// For our other protocols rejection cases, agnhost will return 'REFUSED'.
	countRejected := strings.Count(stderr, "REFUSED") + strings.Count(stderr, "no route to host") + strings.Count(stderr, "permission denied")

	countSCTPInProgress := strings.Count(stderr, "OTHER: operation already in progress")

	if countRejected == 0 && countConnected > 0 {
		return Connected
	}
	if countConnected == 0 && countRejected > 0 {
		return Rejected
	}
	if countDropped+countSCTPInProgress == probeNum {
		return Dropped
	}
	return Error
}

func (k *KubernetesUtils) pingProbe(
	pod *v1.Pod,
	podName string,
	containerName string,
	dstAddr string,
	dstName string,
) PodConnectivityMark {
	pingCmd := fmt.Sprintf("ping -4 -c 3 -W 1 %s", dstAddr)
	if strings.Contains(dstAddr, ":") {
		pingCmd = fmt.Sprintf("ping -6 -c 3 -W 1 %s", dstAddr)
	}
	cmd := []string{
		"/bin/sh",
		"-c",
		pingCmd,
	}
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", pod.Name, containerName, pod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.RunCommandFromPod(pod.Namespace, pod.Name, containerName, cmd)
	log.Tracef("%s -> %s: error when running command: err - %v /// stdout - %s /// stderr - %s", podName, dstName, err, stdout, stderr)
	return decidePingProbeResult(stdout, 3)
}

// decidePingProbeResult uses the pingProbe stdout to decide the connectivity.
func decidePingProbeResult(stdout string, probeNum int) PodConnectivityMark {
	// Provide stdout example for different connectivity:
	// ================== Connected stdout ==================
	// PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
	// 64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=0.695 ms
	// 64 bytes from 10.10.1.2: icmp_seq=2 ttl=64 time=0.250 ms
	// 64 bytes from 10.10.1.2: icmp_seq=3 ttl=64 time=0.058 ms
	//
	// --- 10.10.1.2 ping statistics ---
	// 3 packets transmitted, 3 received, 0% packet loss, time 2043ms
	// rtt min/avg/max/mdev = 0.058/0.334/0.695/0.266 ms
	// ======================================================
	// =================== Dropped stdout ===================
	// PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
	//
	// --- 10.10.1.2 ping statistics ---
	// 3 packets transmitted, 0 received, 100% packet loss, time 2037ms
	// =======================================================
	// =================== Rejected stdout ===================
	// PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
	// From 10.10.1.2 icmp_seq=1 Destination Host Prohibited
	// From 10.10.1.2 icmp_seq=2 Destination Host Prohibited
	// From 10.10.1.2 icmp_seq=3 Destination Host Prohibited
	//
	// --- 10.10.1.2 ping statistics ---
	// 3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2042ms
	// =======================================================
	// =================== Rejected ICMPv6 stdout ===================
	// PING fd02:0:0:f8::11(fd02:0:0:f8::11) 56 data bytes
	// From fd02:0:0:f8::11 icmp_seq=1 Destination unreachable: Administratively prohibited
	// From fd02:0:0:f8::11 icmp_seq=2 Destination unreachable: Administratively prohibited
	// From fd02:0:0:f8::11 icmp_seq=3 Destination unreachable: Administratively prohibited
	//
	// --- fd02:0:0:f8::11 ping statistics ---
	// 3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2047ms
	// =======================================================
	countConnected := strings.Count(stdout, "bytes from")
	countRejected := strings.Count(stdout, "Prohibited") + strings.Count(stdout, "prohibited")
	countDropped := probeNum - strings.Count(stdout, "icmp_seq")

	if countRejected == 0 && countConnected > 0 {
		return Connected
	}
	if countConnected == 0 && countRejected > 0 {
		return Rejected
	}
	if countDropped == probeNum {
		return Dropped
	}
	return Error
}

func (k *KubernetesUtils) digDNS(
	podName string,
	podNamespace string,
	dstAddr string,
	useTCP bool,
) (string, error) {
	pod, err := k.GetPodByLabel(podNamespace, podName)
	if err != nil {
		return "", fmt.Errorf("Pod %s/%s dones't exist", podNamespace, podName)
	}
	digCmd := fmt.Sprintf("dig %s", dstAddr)
	if useTCP {
		digCmd += " +tcp"
	}
	cmd := []string{
		"/bin/sh",
		"-c",
		digCmd,
	}
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", pod.Name, pod.Spec.Containers[0].Name, pod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.RunCommandFromPod(pod.Namespace, pod.Name, pod.Spec.Containers[0].Name, cmd)
	log.Tracef("%s -> %s: error when running command: err - %v /// stdout - %s /// stderr - %s", podName, dstAddr, err, stdout, stderr)
	//========DiG command stdout example========
	//; <<>> DiG 9.16.6 <<>> github.com +tcp
	//;; global options: +cmd
	//;; Got answer:
	//;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21816
	//;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
	//
	//;; OPT PSEUDOSECTION:
	//; EDNS: version: 0, flags:; udp: 4096
	//; COOKIE: 2d7fe493ea37c430 (echoed)
	//;; QUESTION SECTION:
	//;github.com.			IN	A
	//
	//;; ANSWER SECTION:
	//github.com.		6	IN	A	140.82.113.3
	//
	//;; Query time: 0 msec
	//;; SERVER: 10.96.0.10#53(10.96.0.10)
	//;; WHEN: Tue Feb 14 22:34:23 UTC 2023
	//;; MSG SIZE  rcvd: 77
	//==========================================
	answerMarkIdx := strings.Index(stdout, ";; ANSWER SECTION:")
	if answerMarkIdx == -1 {
		return "", fmt.Errorf("failed to parse dig response")
	}
	splitResp := strings.Split(stdout[answerMarkIdx:], "\n")
	if len(splitResp) < 2 {
		return "", fmt.Errorf("failed to parse dig response")
	}
	ipLine := splitResp[1]
	lastTab := strings.LastIndex(ipLine, "\t")
	if lastTab == -1 {
		return "", fmt.Errorf("failed to parse dig response")
	}
	return ipLine[lastTab:], nil
}

// Probe execs into a Pod and checks its connectivity to another Pod. It assumes
// that the target Pod is serving on the input port, and also that agnhost is
// installed. The connectivity from source Pod to all IPs of the target Pod
// should be consistent. Otherwise, Error PodConnectivityMark will be returned.
func (k *KubernetesUtils) Probe(ns1, pod1, ns2, pod2 string, port int32, protocol utils.AntreaPolicyProtocol,
	remoteCluster *KubernetesUtils, expectedResult *PodConnectivityMark) (PodConnectivityMark, error) {
	fromPods, err := k.GetPodsByLabel(ns1, "pod", pod1)
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s: %v", ns1, err)
	}
	if len(fromPods) == 0 {
		return Error, fmt.Errorf("no Pod of label pod=%s in Namespace %s found", pod1, ns1)
	}
	fromPod := fromPods[0]

	var toPods []v1.Pod
	var clusterType string
	if remoteCluster != nil {
		toPods, err = remoteCluster.GetPodsByLabel(ns2, "pod", pod2)
		clusterType = "remote"
	} else {
		toPods, err = k.GetPodsByLabel(ns2, "pod", pod2)
		clusterType = "local"
	}
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s in %s cluster: %v", ns2, clusterType, err)
	}
	if len(toPods) == 0 {
		return Error, fmt.Errorf("no Pod of label pod=%s in Namespace %s found in %s cluster", pod2, ns2, clusterType)
	}
	toPod := toPods[0]
	fromPodName, toPodName := fmt.Sprintf("%s/%s", ns1, pod1), fmt.Sprintf("%s/%s", ns2, pod2)
	return k.probeAndDecideConnectivity(fromPod, toPod, fromPodName, toPodName, port, protocol, expectedResult)
}

func (k *KubernetesUtils) probeAndDecideConnectivity(fromPod, toPod v1.Pod,
	fromPodName, toPodName string, port int32, protocol utils.AntreaPolicyProtocol, expectedResult *PodConnectivityMark) (PodConnectivityMark, error) {
	// Both IPv4 and IPv6 address should be tested.
	connectivity := Unknown
	for _, eachIP := range toPod.Status.PodIPs {
		toIP := eachIP.IP
		// If it's an IPv6 address, add "[]" around it.
		if strings.Contains(toIP, ":") {
			toIP = fmt.Sprintf("[%s]", toIP)
		}
		// HACK: inferring container name as c80, c81 etc., for simplicity.
		containerName := fmt.Sprintf("c%v", port)
		curConnectivity := k.probe(&fromPod, fromPodName, containerName, toIP, toPodName, port, protocol, expectedResult)
		if connectivity == Unknown {
			connectivity = curConnectivity
		} else if connectivity != curConnectivity {
			return Error, nil
		}
	}
	return connectivity, nil
}

// ProbeAddr execs into a Pod and checks its connectivity to an arbitrary destination
// address.
func (k *KubernetesUtils) ProbeAddr(ns, podLabelKey, podLabelValue, dstAddr string, port int32, protocol utils.AntreaPolicyProtocol, expectedResult *PodConnectivityMark) (PodConnectivityMark, error) {
	fromPods, err := k.GetPodsByLabel(ns, podLabelKey, podLabelValue)
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s: %v", ns, err)
	}
	if len(fromPods) == 0 {
		return Error, fmt.Errorf("no Pod of label podLabelKey=%s podLabelValue=%s in Namespace %s found", podLabelKey, podLabelValue, ns)
	}
	fromPod := fromPods[0]
	containerName := fromPod.Spec.Containers[0].Name
	var connectivity PodConnectivityMark
	if protocol == utils.ProtocolICMP {
		connectivity = k.pingProbe(&fromPod, fmt.Sprintf("%s/%s", ns, podLabelValue), containerName, dstAddr, dstAddr)
	} else {
		// If it's an IPv6 address, add "[]" around it.
		if strings.Contains(dstAddr, ":") {
			dstAddr = fmt.Sprintf("[%s]", dstAddr)
		}
		connectivity = k.probe(&fromPod, fmt.Sprintf("%s/%s", ns, podLabelValue), containerName, dstAddr, dstAddr, port, protocol, expectedResult)
	}
	return connectivity, nil
}

// CreateOrUpdateNamespace is a convenience function for idempotent setup of Namespaces
func (data *TestData) CreateOrUpdateNamespace(n string, labels map[string]string) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n,
			Labels: labels,
		},
	}
	nsr, err := data.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Created Namespace %s", n)
		return nsr, nil
	}

	log.Debugf("Unable to create Namespace %s, let's try updating it instead (error: %s)", ns.Name, err)
	nsr, err = data.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("Unable to update Namespace %s: %s", ns, err)
	}

	return nsr, err
}

// CreateOrUpdateDeployment is a convenience function for idempotent setup of deployments
func (data *TestData) CreateOrUpdateDeployment(ns string,
	deploymentName string,
	replicas int32,
	labels map[string]string,
	nodeName string,
	hostNetwork bool) (*appsv1.Deployment, error) {
	zero := int64(0)
	log.Infof("Creating/updating Deployment '%s/%s'", ns, deploymentName)
	makeContainerSpec := func(port int32, protocol v1.Protocol) v1.Container {
		var args []string
		switch protocol {
		case v1.ProtocolTCP:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --tcp --http=false --port=%d", port)}
		case v1.ProtocolUDP:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port=%d", port)}
		case v1.ProtocolSCTP:
			args = []string{"/agnhost porter"}
		default:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port=%d & /agnhost serve-hostname --tcp --http=false --port=%d & /agnhost porter", port, port)}

		}
		return v1.Container{
			Name:            fmt.Sprintf("c%d", port),
			ImagePullPolicy: v1.PullIfNotPresent,
			Image:           agnhostImage,
			Env:             []v1.EnvVar{{Name: fmt.Sprintf("SERVE_SCTP_PORT_%d", port), Value: "foo"}},
			Command:         []string{"/bin/bash", "-c"},
			Args:            args,
			SecurityContext: &v1.SecurityContext{},
			Ports: []v1.ContainerPort{
				{
					ContainerPort: port,
					Name:          fmt.Sprintf("serve-%d", port),
				},
			},
		}
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Labels:    labels,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:    labels,
					Namespace: ns,
				},
				Spec: v1.PodSpec{
					NodeName:                      nodeName,
					HostNetwork:                   hostNetwork,
					TerminationGracePeriodSeconds: &zero,
					Containers: []v1.Container{
						makeContainerSpec(80, "ALL"),
						makeContainerSpec(81, "ALL"),
						makeContainerSpec(8080, v1.ProtocolTCP),
						makeContainerSpec(8081, v1.ProtocolTCP),
						makeContainerSpec(8082, v1.ProtocolTCP),
						makeContainerSpec(8083, v1.ProtocolTCP),
						makeContainerSpec(8084, v1.ProtocolTCP),
						makeContainerSpec(8085, v1.ProtocolTCP),
					},
				},
			},
		},
	}

	d, err := data.clientset.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Created deployment '%s/%s'", ns, d.Name)
		return d, nil
	}

	log.Debugf("Unable to create deployment %s in Namespace %s, let's try update instead", deployment.Name, ns)
	d, err = data.clientset.AppsV1().Deployments(ns).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("Unable to update deployment '%s/%s': %s", ns, deployment.Name, err)
	}
	return d, err
}

// BuildService is a convenience function for building a corev1.Service spec.
func (data *TestData) BuildService(svcName, svcNS string, port, targetPort int, selector map[string]string, serviceType *v1.ServiceType) *v1.Service {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: svcNS,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Port:       int32(port),
				TargetPort: intstr.FromInt(targetPort),
			}},
			Selector: selector,
		},
	}
	if serviceType != nil {
		service.Spec.Type = *serviceType
	}
	return service
}

// CreateOrUpdateService is a convenience function for updating/creating Services.
func (data *TestData) CreateOrUpdateService(svc *v1.Service) (*v1.Service, error) {
	log.Infof("Creating/updating Service %s in ns %s", svc.Name, svc.Namespace)
	svcReturned, err := data.clientset.CoreV1().Services(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})

	if err != nil {
		service, err := data.clientset.CoreV1().Services(svc.Namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create Service %s/%s: %s", svc.Namespace, svc.Name, err)
			return nil, err
		}
		return service, nil
	} else if svcReturned.Name != "" {
		log.Debugf("Service %s/%s already exists, updating", svc.Namespace, svc.Name)
		clusterIP := svcReturned.Spec.ClusterIP
		svcReturned.Spec = svc.Spec
		svcReturned.Spec.ClusterIP = clusterIP
		service, err := data.clientset.CoreV1().Services(svc.Namespace).Update(context.TODO(), svcReturned, metav1.UpdateOptions{})
		return service, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Service %s", svc.Name)
}

// GetService is a convenience function for getting Service
func (data *TestData) GetService(namespace, name string) (*v1.Service, error) {
	return data.clientset.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (data *TestData) GetConfigMap(namespace, name string) (*v1.ConfigMap, error) {
	return data.clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (data *TestData) UpdateConfigMap(configMap *v1.ConfigMap) error {
	_, err := data.clientset.CoreV1().ConfigMaps(configMap.Namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
	return err
}

// DeleteService is a convenience function for deleting a Service by Namespace and name.
func (data *TestData) DeleteService(ns, name string) error {
	log.Infof("Deleting Service %s in ns %s", name, ns)
	err := data.clientset.CoreV1().Services(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to delete Service %s: %w", name, err)
	}
	return nil
}

// CleanServices is a convenience function for deleting Services in the cluster.
func (data *TestData) CleanServices(namespaces map[string]string) error {
	for _, ns := range namespaces {
		l, err := data.clientset.CoreV1().Services(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("unable to list Services in ns %s: %w", ns, err)
		}
		for _, svc := range l.Items {
			if err := data.DeleteService(svc.Namespace, svc.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildServiceAccount is a convenience function for building a corev1.SerivceAccount spec.
func (data *TestData) BuildServiceAccount(name, ns string, labels map[string]string) *v1.ServiceAccount {
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
	}
	return serviceAccount
}

// CreateOrUpdateServiceAccount is a convenience function for updating/creating ServiceAccount.
func (data *TestData) CreateOrUpdateServiceAccount(sa *v1.ServiceAccount) (*v1.ServiceAccount, error) {
	log.Infof("Creating/updating ServiceAccount %s in ns %s", sa.Name, sa.Namespace)
	saReturned, err := data.clientset.CoreV1().ServiceAccounts(sa.Namespace).Get(context.TODO(), sa.Name, metav1.GetOptions{})

	if err != nil {
		serviceAccount, err := data.clientset.CoreV1().ServiceAccounts(sa.Namespace).Create(context.TODO(), sa, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create ServiceAccount %s/%s: %s", sa.Namespace, sa.Name, err)
			return nil, err
		}
		return serviceAccount, nil
	}
	log.Debugf("ServiceAccount %s/%s already exists, updating", sa.Namespace, sa.Name)
	saReturned.Labels = sa.Labels
	serviceAccount, err := data.clientset.CoreV1().ServiceAccounts(sa.Namespace).Update(context.TODO(), saReturned, metav1.UpdateOptions{})
	if err != nil {
		log.Infof("Unable to update ServiceAccount %s/%s: %s", sa.Namespace, sa.Name, err)
		return nil, err
	}
	return serviceAccount, nil
}

// DeleteServiceAccount is a convenience function for deleting a ServiceAccount by Namespace and name.
func (data *TestData) DeleteServiceAccount(ns, name string) error {
	log.Infof("Deleting ServiceAccount %s in ns %s", name, ns)
	err := data.clientset.CoreV1().ServiceAccounts(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to delete ServiceAccount %s in ns %s: %w", name, ns, err)
	}
	return nil
}

// CreateOrUpdateNetworkPolicy is a convenience function for updating/creating netpols. Updating is important since
// some tests update a network policy to confirm that mutation works with a CNI.
func (data *TestData) CreateOrUpdateNetworkPolicy(netpol *v1net.NetworkPolicy) (*v1net.NetworkPolicy, error) {
	log.Infof("Creating/updating NetworkPolicy '%s/%s'", netpol.Namespace, netpol.Name)
	np, err := data.clientset.NetworkingV1().NetworkPolicies(netpol.Namespace).Update(context.TODO(), netpol, metav1.UpdateOptions{})
	if err == nil {
		return np, err
	}

	log.Debugf("Unable to update NetworkPolicy '%s/%s', let's try creating it instead (error: %s)", netpol.Namespace, netpol.Name, err)
	np, err = data.clientset.NetworkingV1().NetworkPolicies(netpol.Namespace).Create(context.TODO(), netpol, metav1.CreateOptions{})
	if err != nil {
		log.Debugf("Unable to create network policy: %s", err)
	}
	return np, err
}

// GetNetworkPolicy is a convenience function for getting k8s NetworkPolicies.
func (data *TestData) GetNetworkPolicy(namespace, name string) (*v1net.NetworkPolicy, error) {
	return data.clientset.NetworkingV1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// DeleteNetworkPolicy is a convenience function for deleting NetworkPolicy by name and Namespace.
func (data *TestData) DeleteNetworkPolicy(ns, name string) error {
	log.Infof("Deleting NetworkPolicy '%s/%s'", ns, name)
	err := data.clientset.NetworkingV1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to delete NetworkPolicy '%s': %w", name, err)
	}
	return nil
}

// CleanNetworkPolicies is a convenience function for deleting NetworkPolicies in the provided namespaces.
func (data *TestData) CleanNetworkPolicies(namespaces map[string]TestNamespaceMeta) error {
	for _, ns := range namespaces {
		if err := data.clientset.NetworkingV1().NetworkPolicies(ns.Name).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
			return fmt.Errorf("unable to delete NetworkPolicies in Namespace '%s': %w", ns, err)
		}
	}
	return nil
}

// CreateTier is a convenience function for creating an Antrea Policy Tier by name and priority.
func (data *TestData) CreateTier(name string, tierPriority int32) (*crdv1beta1.Tier, error) {
	log.Infof("Creating tier %s", name)
	tr := &crdv1beta1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       crdv1beta1.TierSpec{Priority: tierPriority},
	}
	return data.crdClient.CrdV1beta1().Tiers().Create(context.TODO(), tr, metav1.CreateOptions{})
}

// GetTier is a convenience function for getting Tier.
func (data *TestData) GetTier(name string) (*crdv1beta1.Tier, error) {
	return data.crdClient.CrdV1beta1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
}

// UpdateTier is a convenience function for updating an Antrea Policy Tier.
func (data *TestData) UpdateTier(tier *crdv1beta1.Tier) (*crdv1beta1.Tier, error) {
	log.Infof("Updating tier %s", tier.Name)
	return data.crdClient.CrdV1beta1().Tiers().Update(context.TODO(), tier, metav1.UpdateOptions{})
}

func isReferencedError(err error) bool {
	if status, ok := err.(apierrors.APIStatus); ok || errors.As(err, &status) {
		// The message is set by deleteValidate of tierValidator when deleting a Tier that is referenced by any policies.
		return strings.Contains(status.Status().Message, "is referenced by")
	}
	return false
}

// DeleteTier is a convenience function for deleting an Antrea Policy Tier with specific name.
// To avoid flakes caused by antrea-controller not in sync with kube-apiserver, it retries a few times if the failure is
// because the Tier is still referenced.
func (data *TestData) DeleteTier(name string) error {
	log.Infof("Deleting tier %s", name)
	if err := retry.OnError(retry.DefaultRetry, isReferencedError, func() error {
		return data.crdClient.CrdV1beta1().Tiers().Delete(context.TODO(), name, metav1.DeleteOptions{})
	}); err != nil {
		return fmt.Errorf("unable to delete tier %s: %w", name, err)
	}
	return nil
}

// CreateOrUpdateCG is a convenience function for idempotent setup of crd/v1beta1 ClusterGroups
func (data *TestData) CreateOrUpdateCG(cg *crdv1beta1.ClusterGroup) (*crdv1beta1.ClusterGroup, error) {
	log.Infof("Creating/updating ClusterGroup %s", cg.Name)
	cgReturned, err := data.crdClient.CrdV1beta1().ClusterGroups().Get(context.TODO(), cg.Name, metav1.GetOptions{})
	if err != nil {
		cgr, err := data.crdClient.CrdV1beta1().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create cluster group %s: %v", cg.Name, err)
			return nil, err
		}
		return cgr, nil
	} else if cgReturned.Name != "" {
		log.Debugf("ClusterGroup with name %s already exists, updating", cg.Name)
		cgReturned.Spec = cg.Spec
		cgr, err := data.crdClient.CrdV1beta1().ClusterGroups().Update(context.TODO(), cgReturned, metav1.UpdateOptions{})
		return cgr, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterGroup %s", cg.Name)
}

// CreateOrUpdateGroup is a convenience function for idempotent setup of crd/v1beta1 Groups
func (k *KubernetesUtils) CreateOrUpdateGroup(g *crdv1beta1.Group) (*crdv1beta1.Group, error) {
	log.Infof("Creating/updating Group %s/%s", g.Namespace, g.Name)
	gReturned, err := k.crdClient.CrdV1beta1().Groups(g.Namespace).Get(context.TODO(), g.Name, metav1.GetOptions{})
	if err != nil {
		gr, err := k.crdClient.CrdV1beta1().Groups(g.Namespace).Create(context.TODO(), g, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create group %s/%s: %v", g.Namespace, g.Name, err)
			return nil, err
		}
		return gr, nil
	} else if gReturned.Name != "" {
		log.Debugf("Group %s/%s already exists, updating", g.Namespace, g.Name)
		gReturned.Spec = g.Spec
		gr, err := k.crdClient.CrdV1beta1().Groups(g.Namespace).Update(context.TODO(), gReturned, metav1.UpdateOptions{})
		return gr, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Group %s/%s", g.Namespace, g.Name)
}

// GetCG is a convenience function for getting ClusterGroups
func (k *KubernetesUtils) GetCG(name string) (*crdv1beta1.ClusterGroup, error) {
	return k.crdClient.CrdV1beta1().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
}

// GetGroup is a convenience function for getting Groups
func (k *KubernetesUtils) GetGroup(namespace, name string) (*crdv1beta1.Group, error) {
	return k.crdClient.CrdV1beta1().Groups(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// DeleteCG is a convenience function for deleting core/v1beta1 ClusterGroup by name.
func (data *TestData) DeleteCG(name string) error {
	log.Infof("Deleting ClusterGroup %s", name)
	return data.crdClient.CrdV1beta1().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// DeleteGroup is a convenience function for deleting core/v1beta1 Group by namespace and name.
func (k *KubernetesUtils) DeleteGroup(namespace, name string) error {
	log.Infof("Deleting Group %s/%s", namespace, name)
	return k.crdClient.CrdV1beta1().Groups(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// CleanCGs is a convenience function for deleting all ClusterGroups in the cluster.
func (data *TestData) CleanCGs() error {
	return data.crdClient.CrdV1beta1().ClusterGroups().DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
}

// CleanGroups is a convenience function for deleting all Groups in the namespace.
func (k *KubernetesUtils) CleanGroups(namespace string) error {
	return k.crdClient.CrdV1beta1().Groups(namespace).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
}

// CreateOrUpdateACNP is a convenience function for updating/creating AntreaClusterNetworkPolicies.
func (data *TestData) CreateOrUpdateACNP(cnp *crdv1beta1.ClusterNetworkPolicy) (*crdv1beta1.ClusterNetworkPolicy, error) {
	log.Infof("Creating/updating ClusterNetworkPolicy %s", cnp.Name)
	cnpReturned, err := data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Get(context.TODO(), cnp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating ClusterNetworkPolicy %s", cnp.Name)
		cnp, err = data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Create(context.TODO(), cnp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create ClusterNetworkPolicy: %s", err)
		}
		return cnp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("ClusterNetworkPolicy with name %s already exists, updating", cnp.Name)
		cnpReturned.Spec = cnp.Spec
		cnp, err = data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Update(context.TODO(), cnpReturned, metav1.UpdateOptions{})
		return cnp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterNetworkPolicy %s", cnp.Name)
}

// GetACNP is a convenience function for getting AntreaClusterNetworkPolicies.
func (data *TestData) GetACNP(name string) (*crdv1beta1.ClusterNetworkPolicy, error) {
	return data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Get(context.TODO(), name, metav1.GetOptions{})
}

// DeleteACNP is a convenience function for deleting ACNP by name.
func (data *TestData) DeleteACNP(name string) error {
	log.Infof("Deleting AntreaClusterNetworkPolicies %s", name)
	return data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// CleanACNPs is a convenience function for deleting all Antrea ClusterNetworkPolicies in the cluster.
func (data *TestData) CleanACNPs() error {
	return data.crdClient.CrdV1beta1().ClusterNetworkPolicies().DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
}

// CreateOrUpdateANNP is a convenience function for updating/creating Antrea NetworkPolicies.
func (data *TestData) CreateOrUpdateANNP(annp *crdv1beta1.NetworkPolicy) (*crdv1beta1.NetworkPolicy, error) {
	log.Infof("Creating/updating Antrea NetworkPolicy %s/%s", annp.Namespace, annp.Name)
	npReturned, err := data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Get(context.TODO(), annp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating Antrea NetworkPolicy %s", annp.Name)
		annp, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Create(context.TODO(), annp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create Antrea NetworkPolicy: %s", err)
		}
		return annp, err
	} else if npReturned.Name != "" {
		log.Debugf("Antrea NetworkPolicy with name %s already exists, updating", annp.Name)
		npReturned.Spec = annp.Spec
		annp, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Update(context.TODO(), npReturned, metav1.UpdateOptions{})
		return annp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Antrea NetworkPolicy %s", annp.Name)
}

// GetANNP is a convenience function for getting AntreaNetworkPolicies.
func (data *TestData) GetANNP(namespace, name string) (*crdv1beta1.NetworkPolicy, error) {
	return data.crdClient.CrdV1beta1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// DeleteANNP is a convenience function for deleting ANNP by name and Namespace.
func (data *TestData) DeleteANNP(ns, name string) error {
	log.Infof("Deleting Antrea NetworkPolicy '%s/%s'", ns, name)
	return data.crdClient.CrdV1beta1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// CleanANNPs is a convenience function for deleting all Antrea NetworkPolicies in provided namespaces.
func (data *TestData) CleanANNPs(namespaces []string) error {
	for _, ns := range namespaces {
		if err := data.crdClient.CrdV1beta1().NetworkPolicies(ns).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
			return fmt.Errorf("unable to delete Antrea NetworkPolicies in ns %s: %w", ns, err)
		}
	}
	return nil
}

func (data *TestData) WaitForANNPCreationAndRealization(t *testing.T, namespace string, name string, timeout time.Duration) error {
	t.Logf("Waiting for ANNP '%s/%s' to be realized", namespace, name)
	if err := wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		annp, err := data.crdClient.CrdV1beta1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return annp.Status.ObservedGeneration == annp.Generation && annp.Status.Phase == crdv1beta1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ANNP '%s/%s' to be realized: %v", namespace, name, err)
	}
	return nil
}

func (data *TestData) WaitForACNPCreationAndRealization(t *testing.T, name string, timeout time.Duration) error {
	t.Logf("Waiting for ACNP '%s' to be created and realized", name)
	if err := wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		acnp, err := data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return acnp.Status.ObservedGeneration == acnp.Generation && acnp.Status.Phase == crdv1beta1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ACNP '%s' to be realized: %v", name, err)
	}
	return nil
}

func (k *KubernetesUtils) waitForPodInNamespace(ns string, pod string) ([]string, error) {
	log.Infof("Waiting for Pod '%s/%s'", ns, pod)
	for {
		k8sPod, err := k.GetPodByLabel(ns, pod)
		if err != nil && err != ErrPodNotFound {
			return nil, fmt.Errorf("unable to get Pod '%s/%s': %w", ns, pod, err)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return nil, fmt.Errorf("unable to get IP of Pod '%s/%s': %w", ns, pod, err)
			}
			var podIPs []string
			for _, podIP := range k8sPod.Status.PodIPs {
				podIPs = append(podIPs, podIP.IP)
			}
			log.Debugf("IPs of Pod '%s/%s': %s", ns, pod, podIPs)
			log.Debugf("Pod running: %s/%s", ns, pod)
			return podIPs, nil
		}
		log.Infof("Pod '%s/%s' not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func (k *KubernetesUtils) waitForHTTPServers(allPods []Pod) error {
	const maxTries = 10
	log.Infof("waiting for HTTP servers (ports 80, 81 and 8080:8085) to become ready")

	serversAreReady := func() bool {
		reachability := NewReachability(allPods, Connected)
		k.Validate(allPods, reachability, []int32{80, 81, 8080, 8081, 8082, 8083, 8084, 8085}, utils.ProtocolTCP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}

		k.Validate(allPods, reachability, []int32{80, 81}, utils.ProtocolUDP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}

		k.Validate(allPods, reachability, []int32{80, 81}, utils.ProtocolSCTP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}
		return true
	}

	for i := 0; i < maxTries; i++ {
		if serversAreReady() {
			log.Infof("All HTTP servers are ready")
			return nil
		}
		time.Sleep(defaultInterval)
	}
	return fmt.Errorf("after %d tries, HTTP servers are not ready", maxTries)
}

func (k *KubernetesUtils) validateOnePort(allPods []Pod, reachability *Reachability, port int32, protocol utils.AntreaPolicyProtocol) {
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo Pod, port int32) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		expectedResult := reachability.Expected.Get(podFrom.String(), podTo.String())
		connectivity, err := k.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port, protocol, nil, &expectedResult)
		resultsCh <- &probeResult{podFrom, podTo, connectivity, err}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2, port)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		if r.err != nil {
			log.Errorf("unable to perform probe %s -> %s: %v", r.podFrom, r.podTo, r.err)
		}

		// We will receive the connectivity from podFrom to podTo len(ports) times, where
		// ports is the parameter to the Validate method.
		// If it's the first time we observe the connectivity from podFrom to podTo, just
		// store the connectivity we received in reachability matrix.
		// If the connectivity from podFrom to podTo has been observed and is different
		// from the connectivity we received, store Error connectivity in reachability
		// matrix.
		prevConn := reachability.Observed.Get(r.podFrom.String(), r.podTo.String())
		if prevConn == Unknown {
			reachability.Observe(r.podFrom, r.podTo, r.connectivity)
		} else if prevConn != r.connectivity {
			reachability.Observe(r.podFrom, r.podTo, Error)
		}
	}
}

// Validate checks the connectivity between all Pods in both directions with a
// list of ports and a protocol. The connectivity from a Pod to another Pod should
// be consistent across all provided ports. Otherwise, this connectivity will be
// treated as Error.
func (k *KubernetesUtils) Validate(allPods []Pod, reachability *Reachability, ports []int32, protocol utils.AntreaPolicyProtocol) {
	for _, port := range ports {
		// we do not run all the probes in parallel as we have experienced that on some
		// machines, this can cause a fraction of the probes to always fail, despite the
		// built-in retry (3x) mechanism. Probably because of the large number of probes,
		// each one being executed in its own goroutine. For example, with 9 Pods and for
		// ports 80, 81, 8080, 8081, 8082, 8083, 8084 and 8085, we would end up with
		// potentially 9*9*8 = 648 simultaneous probes.
		k.validateOnePort(allPods, reachability, port, protocol)
	}
}

func (k *KubernetesUtils) ValidateRemoteCluster(remoteCluster *KubernetesUtils, allPods []Pod, reachability *Reachability, port int32, protocol utils.AntreaPolicyProtocol) {
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	oneProbe := func(podFrom, podTo Pod, port int32) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		expectedResult := reachability.Expected.Get(podFrom.String(), podTo.String())
		connectivity, err := k.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port, protocol, remoteCluster, &expectedResult)
		resultsCh <- &probeResult{podFrom, podTo, connectivity, err}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2, port)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		if r.err != nil {
			log.Errorf("unable to perform probe %s -> %s in %s: %v", r.podFrom, r.podTo, k.ClusterName, r.err)
		}
		prevConn := reachability.Observed.Get(r.podFrom.String(), r.podTo.String())
		if prevConn == Unknown {
			reachability.Observe(r.podFrom, r.podTo, r.connectivity)
		}
	}
}

func (k *KubernetesUtils) Bootstrap(namespaces map[string]TestNamespaceMeta, podsPerNamespace []string, createNamespaces bool, nodeNames map[string]string, hostNetworks map[string]bool) (map[string][]string, error) {
	for key, ns := range namespaces {
		if createNamespaces {
			if ns.Labels == nil {
				ns.Labels = make(map[string]string)
			}
			// convenience label for testing
			ns.Labels["ns"] = ns.Name
			if _, err := k.CreateOrUpdateNamespace(ns.Name, ns.Labels); err != nil {
				return nil, fmt.Errorf("unable to create/update ns %s: %w", ns, err)
			}
		}
		var nodeName string
		var hostNetwork bool
		if nodeNames != nil {
			nodeName = nodeNames[key]
		}
		if hostNetworks != nil {
			hostNetwork = hostNetworks[key]
		}
		for _, pod := range podsPerNamespace {
			log.Infof("Creating/updating Pod '%s/%s'", ns, pod)
			deployment := ns.Name + pod
			_, err := k.CreateOrUpdateDeployment(ns.Name, deployment, 1, map[string]string{"pod": pod, "app": pod}, nodeName, hostNetwork)
			if err != nil {
				return nil, fmt.Errorf("unable to create/update Deployment '%s/%s': %w", ns, pod, err)
			}
		}
	}
	var allPods []Pod
	podIPs := make(map[string][]string, len(podsPerNamespace)*len(namespaces))
	for _, podName := range podsPerNamespace {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns.Name, podName))
		}
	}
	for _, pod := range allPods {
		ips, err := k.waitForPodInNamespace(pod.Namespace(), pod.PodName())
		if ips == nil || err != nil {
			return nil, fmt.Errorf("unable to wait for Pod '%s/%s': %w", pod.Namespace(), pod.PodName(), err)
		}
		podIPs[pod.String()] = ips
	}

	// Ensure that all the HTTP servers have time to start properly.
	// See https://github.com/antrea-io/antrea/issues/472.
	if err := k.waitForHTTPServers(allPods); err != nil {
		return nil, err
	}

	return podIPs, nil
}

func (k *KubernetesUtils) Cleanup(namespaces map[string]TestNamespaceMeta) {
	// Cleanup any cluster-scoped resources.
	if err := k.CleanACNPs(); err != nil {
		log.Errorf("Error when cleaning up ACNPs: %v", err)
	}
	if err := k.CleanCGs(); err != nil {
		log.Errorf("Error when cleaning up CGs: %v", err)
	}

	for _, ns := range namespaces {
		log.Infof("Deleting test Namespace %s", ns)
		if err := k.DeleteNamespace(ns.Name, defaultTimeout); err != nil {
			log.Errorf("Error when deleting Namespace '%s': %v", ns, err)
		}
	}
}
