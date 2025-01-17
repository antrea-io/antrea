//go:build windows
// +build windows

// Copyright 2021 Antrea Authors
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

package cniserver

import (
	"time"

	"antrea.io/libOpenflow/openflow15"
	current "github.com/containernetworking/cni/pkg/types/100"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/interfacestore"
)

var (
	workerName = "podConfigurator"
)

const (
	podNotReadyTimeInSeconds = 30 * time.Second
	ovsInterfaceTypeForPod   = "internal"
)

// connectInterfaceToOVSAsync waits for an interface to be created and connects it to OVS br-int asynchronously
// in another goroutine. The function is for containerd runtime. The host interface is created after
// CNI call completes.
func (pc *podConfigurator) connectInterfaceToOVSAsync(ifConfig *interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) error {
	ovsPortName := ifConfig.InterfaceName
	// Add the OVS port into the queue after 30s in case the OFPort is still not ready. This
	// operation is performed before we update OVSDB, otherwise we
	// need to think about the race condition between the current goroutine with the listener.
	// It may generate a duplicated PodIsReady event if the Pod's OpenFlow entries are installed
	// before the time, then the library shall merge the event.
	pc.unreadyPortQueue.AddAfter(ovsPortName, podNotReadyTimeInSeconds)
	return pc.ifConfigurator.addPostInterfaceCreateHook(ifConfig.ContainerID, ovsPortName, containerAccess, func() error {
		if err := pc.ovsBridgeClient.SetInterfaceType(ovsPortName, ovsInterfaceTypeForPod); err != nil {
			return err
		}
		return nil
	})
}

// connectInterfaceToOVS connects an existing interface to the OVS bridge.
func (pc *podConfigurator) connectInterfaceToOVS(
	podName, podNamespace, containerID, netNS string,
	hostIface, containerIface *current.Interface,
	ips []*current.IPConfig,
	vlanID uint16,
	containerAccess *containerAccessArbitrator) (*interfacestore.InterfaceConfig, error) {
	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNamespace, containerIface, ips, vlanID)
	// The container interface is created after the CNI returns the network setup result.
	// Because of this, we need to wait asynchronously for the interface to be created: we create the OVS port
	// and set the OVS Interface type "" first, and change the OVS Interface type to "internal" to connect to the
	// container interface after it is created. After OVS connects to the container interface, an OFPort is allocated.
	klog.V(2).InfoS("Adding OVS port for container", "port", ovsPortName, "container", containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo, containerConfig.VLANID)
	if err != nil {
		return nil, err
	}
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	return containerConfig, pc.connectInterfaceToOVSAsync(containerConfig, containerAccess)
}

func (pc *podConfigurator) configureInterfaces(
	podName, podNamespace, containerID, containerNetNS string,
	containerIFDev string, mtu int, sriovVFDeviceID string,
	result *ipam.IPAMResult, createOVSPort bool, containerAccess *containerAccessArbitrator) error {
	if !createOVSPort {
		return pc.ifConfigurator.configureContainerLink(
			podName, podNamespace, containerID, containerNetNS,
			containerIFDev, mtu, sriovVFDeviceID, "",
			&result.Result, containerAccess)
	}
	// Check if the OVS configurations for the container exists or not. If yes, return
	// immediately. This check is used on Windows, as kubelet on Windows will call CNI ADD
	// multiple times for the infrastructure container to query IP of the Pod. But there should
	// be only one OVS port created for the same Pod (identified by its sandbox container ID),
	// and if the OVS port is added more than once, OVS will return an error.
	// See: https://github.com/kubernetes/kubernetes/issues/57253#issuecomment-358897721.
	interfaceConfig, found := pc.ifaceStore.GetContainerInterface(containerID)
	if found {
		klog.V(2).InfoS("Found an existing OVS port for container, returning", "container", containerID)
		mac := interfaceConfig.MAC.String()
		hostIface := &current.Interface{
			Name:    interfaceConfig.InterfaceName,
			Mac:     mac,
			Sandbox: "",
		}
		containerIface := &current.Interface{
			Name:    containerIFDev,
			Mac:     mac,
			Sandbox: containerNetNS,
		}
		result.Interfaces = []*current.Interface{hostIface, containerIface}
		return nil
	}

	return pc.configureInterfacesCommon(podName, podNamespace, containerID, containerNetNS,
		containerIFDev, mtu, sriovVFDeviceID, result, containerAccess)
}

// isInterfaceInvalid returns false because we now don't support detecting the disconnected host interface on Windows
// due to the OVS issue (https://github.com/openvswitch/ovs-issues/issues/353), by which we can't differentiate from
// the case that a Pod's host interface is created during agent downtime and is expected to re-connect after agent
// is restarted.
func (pc *podConfigurator) isInterfaceInvalid(ifaceConfig *interfacestore.InterfaceConfig) bool {
	return false
}

func (pc *podConfigurator) reconcileMissingPods(ifConfigs []*interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) {
	for i := range ifConfigs {
		ifaceConfig := ifConfigs[i]
		if err := pc.connectInterfaceToOVSAsync(ifaceConfig, containerAccess); err != nil {
			klog.ErrorS(err, "Failed to reconcile Pod", "Pod", klog.KRef(ifaceConfig.PodNamespace, ifaceConfig.PodNamespace))
		}
	}
}

// initPortStatusMonitor has subscribed a channel to listen for the OpenFlow PortStatus message, and it also
// initiates the Pod recorder.
func (pc *podConfigurator) initPortStatusMonitor(podInformer cache.SharedIndexInformer) {
	pc.podLister = v1.NewPodLister(podInformer.GetIndexer())
	pc.podListerSynced = podInformer.HasSynced
	pc.unreadyPortQueue = workqueue.NewTypedDelayingQueueWithConfig[string](
		workqueue.TypedDelayingQueueConfig[string]{
			Name: workerName,
		},
	)
	eventBroadcaster := record.NewBroadcaster()
	pc.eventBroadcaster = eventBroadcaster
	pc.recorder = eventBroadcaster.NewRecorder(
		scheme.Scheme,
		corev1.EventSource{Component: "AntreaPodConfigurator"},
	)
	pc.statusCh = make(chan *openflow15.PortStatus, 100)
	pc.ofClient.SubscribeOFPortStatusMessage(pc.statusCh)
}

func (pc *podConfigurator) Run(stopCh <-chan struct{}) {
	defer pc.unreadyPortQueue.ShutDown()

	klog.Infof("Starting %s", workerName)
	defer klog.Infof("Shutting down %s", workerName)

	if !cache.WaitForNamedCacheSync("podConfigurator", stopCh, pc.podListerSynced) {
		return
	}
	pc.eventBroadcaster.StartStructuredLogging(0)
	pc.eventBroadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{
		Interface: pc.kubeClient.CoreV1().Events(""),
	})
	defer pc.eventBroadcaster.Shutdown()

	go wait.Until(pc.worker, time.Second, stopCh)

	for {
		select {
		case status := <-pc.statusCh:
			klog.V(2).InfoS("Received PortStatus message", "message", status)
			// Update Pod OpenFlow entries only after the OpenFlow port state is live.
			pc.processPortStatusMessage(status)
		case <-stopCh:
			return
		}
	}
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (pc *podConfigurator) worker() {
	for pc.processNextWorkItem() {
	}
}
