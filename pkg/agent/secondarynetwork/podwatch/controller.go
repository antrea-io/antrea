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

package podwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	cnitypes "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	secondaryutil "antrea.io/antrea/pkg/agent/secondarynetwork/util"
	"antrea.io/antrea/pkg/agent/types"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
)

const (
	controllerName = "SecondaryNetworkController"
	minRetryDelay  = 2 * time.Second
	maxRetryDelay  = 120 * time.Second
	numWorkers     = 4
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod = 0 * time.Minute
)

const (
	resourceNameAnnotationKey = "k8s.v1.cni.cncf.io/resourceName"
	startIfaceIndex           = 1
	endIfaceIndex             = 101

	interfaceDefaultMTU = 1500
	vlanIDMax           = 4094
)

var (
	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
)

type InterfaceConfigurator interface {
	ConfigureSriovSecondaryInterface(podName, podNamespace, containerID, containerNetNS, containerInterfaceName string, mtu int, podSriovVFDeviceID string, result *current.Result) error
	DeleteSriovSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error
	ConfigureVLANSecondaryInterface(podName, podNamespace, containerID, containerNetNS, containerInterfaceName string, mtu int, ipamResult *ipam.IPAMResult, mac net.HardwareAddr) error
	DeleteVLANSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error
}

type IPAMAllocator interface {
	SecondaryNetworkAllocate(podOwner *crdv1b1.PodOwner, networkConfig *cnitypes.NetworkConfig) (*ipam.IPAMResult, error)
	SecondaryNetworkRelease(podOwner *crdv1b1.PodOwner) error
}

type podCNIInfo struct {
	containerID string
	netNS       string
}

type PodController struct {
	kubeClient            clientset.Interface
	netAttachDefClient    netdefclient.K8sCniCncfIoV1Interface
	queue                 workqueue.TypedRateLimitingInterface[string]
	podInformer           cache.SharedIndexInformer
	podLister             corelisters.PodLister
	ipPoolLister          crdlisters.IPPoolLister
	podUpdateSubscriber   channel.Subscriber
	ovsBridgeClient       ovsconfig.OVSBridgeClient
	interfaceStore        interfacestore.InterfaceStore
	primaryInterfaceStore interfacestore.InterfaceStore
	interfaceConfigurator InterfaceConfigurator
	ipamAllocator         IPAMAllocator
	// Map from "namespace/pod" to podCNIInfo.
	cniCache           sync.Map
	vfDeviceIDUsageMap sync.Map
	nodeConfig         *config.NodeConfig
}

func NewPodController(
	kubeClient clientset.Interface,
	netAttachDefClient netdefclient.K8sCniCncfIoV1Interface,
	podInformer cache.SharedIndexInformer,
	podUpdateSubscriber channel.Subscriber,
	primaryInterfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ipPoolLister crdlisters.IPPoolLister,
) (*PodController, error) {
	ifaceStore := interfacestore.NewInterfaceStore()
	interfaceConfigurator, err := cniserver.NewSecondaryInterfaceConfigurator(ovsBridgeClient, ifaceStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create SecondaryInterfaceConfigurator: %v", err)
	}
	podLister := corelisters.NewPodLister(podInformer.GetIndexer())
	pc := PodController{
		kubeClient:         kubeClient,
		netAttachDefClient: netAttachDefClient,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "podcontroller",
			},
		),
		podInformer:           podInformer,
		podLister:             podLister,
		ipPoolLister:          ipPoolLister,
		podUpdateSubscriber:   podUpdateSubscriber,
		ovsBridgeClient:       ovsBridgeClient,
		interfaceStore:        ifaceStore,
		primaryInterfaceStore: primaryInterfaceStore,
		interfaceConfigurator: interfaceConfigurator,
		ipamAllocator:         ipam.GetSecondaryNetworkAllocator(),
		nodeConfig:            nodeConfig,
	}
	podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    pc.enqueuePod,
			DeleteFunc: pc.enqueuePod,
			UpdateFunc: func(old, cur interface{}) { pc.enqueuePod(cur) },
		},
		resyncPeriod,
	)

	pc.initializeCNICache()
	if err := pc.initializeOVSSecondaryInterfaceStore(); err != nil {
		return nil, fmt.Errorf("failed to initialize secondary interface store: %w", err)
	}

	// podUpdateSubscriber can be nil with test code.
	if podUpdateSubscriber != nil {
		// Subscribe Pod CNI add/del events.
		podUpdateSubscriber.Subscribe(pc.processCNIUpdate)
	}
	return &pc, nil
}

func podKeyGet(podName, podNamespace string) string {
	return podNamespace + "/" + podName
}

func allocatePodSecondaryIfaceName(usedIFNames sets.Set[string]) (string, error) {
	// Generate new interface name (eth1,eth2..eth100) and return to caller.
	for ifaceIndex := startIfaceIndex; ifaceIndex < endIfaceIndex; ifaceIndex++ {
		ifName := fmt.Sprintf("%s%d", "eth", ifaceIndex)
		if !usedIFNames.Has(ifName) {
			usedIFNames.Insert(ifName)
			return ifName, nil
		}
	}
	return "", fmt.Errorf("no more interface names")
}

func (pc *PodController) enqueuePod(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		podDeletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "obj", obj)
			return
		}
		pod, ok = podDeletedState.Obj.(*corev1.Pod)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown object is not of type Pod", "obj", podDeletedState.Obj)
			return
		}
	}
	podKey := podKeyGet(pod.Name, pod.Namespace)
	pc.queue.Add(podKey)
}

// processCNIUpdate will be called when CNIServer publishes a Pod update event.
func (pc *PodController) processCNIUpdate(e interface{}) {
	event := e.(types.PodUpdate)
	podKey := podKeyGet(event.PodName, event.PodNamespace)
	if event.IsAdd {
		pc.cniCache.Store(podKey, &podCNIInfo{containerID: event.ContainerID, netNS: event.NetNS})
	} else {
		pc.cniCache.Delete(podKey)
	}
	pc.queue.Add(podKeyGet(event.PodName, event.PodNamespace))
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (pc *PodController) handleAddUpdatePod(pod *corev1.Pod, podCNIInfo *podCNIInfo, storedSecondaryInterfaces []*interfacestore.InterfaceConfig) error {
	if len(pod.Status.PodIPs) == 0 {
		// Primary network configuration is not complete yet. Return nil here to dequeue the
		// Pod event. Secondary network configuration will be handled with the following Pod
		// update events.
		return nil
	}

	var networkList []*netdefv1.NetworkSelectionElement
	secondaryNetwork, ok := checkForPodSecondaryNetworkAttachment(pod)
	if !ok {
		klog.V(2).InfoS("Pod does not have a NetworkAttachmentDefinition", "Pod", klog.KObj(pod))
	} else {
		// Parse Pod annotation and proceed with the secondary network configuration.
		var err error
		networkList, err = netdefutils.ParseNetworkAnnotation(secondaryNetwork, pod.Namespace)
		if err != nil {
			klog.ErrorS(err, "Error when parsing network annotation", "annotation", secondaryNetwork)
			// Do not return an error as a retry is not appropriate.
			// When the annotation is fixed, the Pod will be enqueued again.
			return nil
		}
	}

	if len(storedSecondaryInterfaces) > 0 {
		if len(networkList) > 0 {
			// We do not support secondary network update at the moment. Return as long as one
			// secondary interface has been created for the Pod.
			klog.V(1).InfoS("Secondary network already configured on this Pod. Changes to secondary network configuration are not supported, skipping update",
				"Pod", klog.KObj(pod))
			return nil
		}
		if err := pc.removeInterfaces(storedSecondaryInterfaces); err != nil {
			return err
		}
	}

	var netStatus []netdefv1.NetworkStatus
	if len(networkList) > 0 {
		var err error
		netStatus, err = pc.configurePodSecondaryNetwork(pod, networkList, podCNIInfo)
		if err != nil {
			return err
		}
	}

	if netStatus != nil {
		// Intentionally ignore errors from updating the Pod's network status annotation here.
		// Failure to update the annotation does not affect the actual network setup for the Pod.
		// The annotation is mainly used for status reporting and restoring SR-IOV interface
		// information after agent restarts.
		_ = pc.updatePodNetworkStatusAnnotation(netStatus, pod)
	} else {
		_ = pc.deletePodNetworkStatusAnnotation(pod)
	}
	return nil
}

func (pc *PodController) deletePodNetworkStatusAnnotation(pod *corev1.Pod) error {
	resultErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pod, err := pc.kubeClient.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, ok := pod.Annotations[netdefv1.NetworkStatusAnnot]; ok {
			delete(pod.Annotations, netdefv1.NetworkStatusAnnot)
			_, err = pc.kubeClient.CoreV1().Pods(pod.Namespace).UpdateStatus(context.TODO(), pod, metav1.UpdateOptions{})
			return err
		}
		return nil
	})
	if resultErr != nil {
		klog.ErrorS(resultErr, "Pod network status annotation delete failed", "Pod", klog.KObj(pod))
		return fmt.Errorf("status delete failed for pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}
	klog.V(2).InfoS("Pod network status annotation deleted", "Pod", klog.KObj(pod))
	return nil
}

var (
	setNetworkStatus = netdefutils.SetNetworkStatus
)

// updatePodNetworkStatusAnnotation update the Pod's network status annotation
func (pc *PodController) updatePodNetworkStatusAnnotation(netStatus []netdefv1.NetworkStatus, pod *corev1.Pod) error {
	storedPrimaryInterfaces := pc.primaryInterfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
	if len(storedPrimaryInterfaces) > 0 {
		primaryInterface := storedPrimaryInterfaces[0]
		primaryNetworkStatus := netdefv1.NetworkStatus{
			Name:      cniserver.AntreaCNIType,
			Interface: primaryInterface.IFDev,
			Mac:       primaryInterface.MAC.String(),
			Default:   true,
		}
		if pc.nodeConfig.GatewayConfig.IPv4 != nil {
			primaryNetworkStatus.Gateway = append(primaryNetworkStatus.Gateway, pc.nodeConfig.GatewayConfig.IPv4.String())
		}
		if pc.nodeConfig.GatewayConfig.IPv6 != nil {
			primaryNetworkStatus.Gateway = append(primaryNetworkStatus.Gateway, pc.nodeConfig.GatewayConfig.IPv6.String())
		}
		for _, ip := range primaryInterface.IPs {
			primaryNetworkStatus.IPs = append(primaryNetworkStatus.IPs, ip.String())
		}
		netStatus = append(netStatus, primaryNetworkStatus)
	}

	// Update the Pod's network status annotation
	if err := setNetworkStatus(pc.kubeClient, pod, netStatus); err != nil {
		klog.ErrorS(err, "Pod network status annotation update failed", "Pod", klog.KObj(pod))
		return err
	}
	klog.V(2).InfoS("Pod network status annotation updated", "Pod", klog.KObj(pod), "NetworkStatus", netStatus)
	return nil
}

func (pc *PodController) removeInterfaces(interfaces []*interfacestore.InterfaceConfig) error {
	var savedErr error
	for _, interfaceConfig := range interfaces {
		podName := interfaceConfig.PodName
		podNamespace := interfaceConfig.PodNamespace
		klog.V(1).InfoS("Deleting secondary interface",
			"Pod", klog.KRef(podNamespace, podName), "interface", interfaceConfig.IFDev)

		var err error
		// Since only VLAN and SR-IOV interfaces are supported by now, we judge the
		// interface type by checking interfaceConfig.OVSPortConfig is set or not.
		if interfaceConfig.OVSPortConfig != nil {
			err = pc.interfaceConfigurator.DeleteVLANSecondaryInterface(interfaceConfig)
		} else {
			err = pc.deleteSriovSecondaryInterface(interfaceConfig)
		}
		if err != nil {
			klog.ErrorS(err, "Error when deleting secondary interface",
				"Pod", klog.KRef(podNamespace, podName), "interface", interfaceConfig.IFDev)
			savedErr = err
			continue
		}

		podOwner := &crdv1b1.PodOwner{
			Name:        interfaceConfig.PodName,
			Namespace:   interfaceConfig.PodNamespace,
			ContainerID: interfaceConfig.ContainerID,
			IFName:      interfaceConfig.IFDev}
		if err = pc.ipamAllocator.SecondaryNetworkRelease(podOwner); err != nil {
			klog.ErrorS(err, "Error when releasing IPAM allocation",
				"Pod", klog.KRef(podNamespace, podName), "interface", interfaceConfig.IFDev)
			savedErr = err
		}
	}
	return savedErr
}

func (pc *PodController) syncPod(key string) error {
	var pod *corev1.Pod
	var cniInfo *podCNIInfo
	podExists := false

	if cniObj, cniAdded := pc.cniCache.Load(key); cniAdded {
		podObj, ok, err := pc.podInformer.GetIndexer().GetByKey(key)
		if err != nil {
			return err
		}
		if ok {
			pod = podObj.(*corev1.Pod)
			cniInfo = cniObj.(*podCNIInfo)
			podExists = true
		}
	}

	namespacePod := strings.Split(key, "/")
	podNamespace := namespacePod[0]
	podName := namespacePod[1]
	storedSecondaryInterfaces := pc.interfaceStore.GetContainerInterfacesByPod(podName, podNamespace)
	if len(storedSecondaryInterfaces) > 0 {
		// Pod or its primary interface has been deleted. Remove secondary interfaces too.
		if !podExists ||
			// Interfaces created for a previous Pod with the same Namespace/name are
			// not deleted yet. First delete them before processing the new Pod's
			// secondary networks.
			storedSecondaryInterfaces[0].ContainerID != cniInfo.containerID {
			if err := pc.removeInterfaces(storedSecondaryInterfaces); err != nil {
				return err
			}
		}
	}

	if !podExists {
		pc.deleteVFDeviceIDListPerPod(podName, podNamespace)
		return nil
	}
	return pc.handleAddUpdatePod(pod, cniInfo, storedSecondaryInterfaces)
}

func (pc *PodController) Worker() {
	for pc.processNextWorkItem() {
	}
}

func (pc *PodController) processNextWorkItem() bool {
	key, quit := pc.queue.Get()
	if quit {
		return false
	}
	defer pc.queue.Done(key)
	if err := pc.syncPod(key); err == nil {
		pc.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing Pod for SecondaryNetwork, requeuing", "key", key)
		pc.queue.AddRateLimited(key)
	}
	return true
}

// Configure Secondary Network Interface.
func (pc *PodController) configureSecondaryInterface(
	pod *corev1.Pod,
	network *netdefv1.NetworkSelectionElement,
	resourceName string,
	podCNIInfo *podCNIInfo,
	networkConfig *SecondaryNetworkConfig,
	mac net.HardwareAddr,
) (*current.Result, error) {
	var ipamResult *ipam.IPAMResult
	var ifConfigErr error
	if networkConfig.IPAM != nil {
		var err error
		podOwner := &crdv1b1.PodOwner{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			ContainerID: podCNIInfo.containerID,
			IFName:      network.InterfaceRequest,
		}
		ipamResult, err = pc.ipamAllocator.SecondaryNetworkAllocate(podOwner, &networkConfig.NetworkConfig)
		if err != nil {
			return nil, fmt.Errorf("secondary network IPAM failed: %v", err)
		}
		defer func() {
			if ifConfigErr != nil {
				// Interface creation failed. Free allocated IP address
				if err := pc.ipamAllocator.SecondaryNetworkRelease(podOwner); err != nil {
					klog.ErrorS(err, "IPAM de-allocation failed", "podOwner", podOwner)
				}
			}
		}()
		for _, ip := range ipamResult.IPs {
			ip.Interface = current.Int(1)
		}
	} else {
		ipamResult = &ipam.IPAMResult{}
	}

	switch networkConfig.NetworkType {
	case sriovNetworkType:
		ifConfigErr = pc.configureSriovAsSecondaryInterface(pod, network, resourceName, podCNIInfo, networkConfig.MTU, &ipamResult.Result)
	case vlanNetworkType:
		if networkConfig.VLAN > 0 {
			// Let VLAN ID in the CNI network configuration override the IPPool subnet
			// VLAN.
			ipamResult.VLANID = uint16(networkConfig.VLAN)
		}
		ifConfigErr = pc.interfaceConfigurator.ConfigureVLANSecondaryInterface(
			pod.Name, pod.Namespace,
			podCNIInfo.containerID, podCNIInfo.netNS, network.InterfaceRequest,
			networkConfig.MTU, ipamResult, mac)
	}
	return &ipamResult.Result, ifConfigErr
}

func (pc *PodController) configurePodSecondaryNetwork(pod *corev1.Pod, networkList []*netdefv1.NetworkSelectionElement, podCNIInfo *podCNIInfo) ([]netdefv1.NetworkStatus, error) {
	usedIFNames := sets.New[string]()
	usedIFMAC := sets.New[string]()
	for _, network := range networkList {
		if network.InterfaceRequest != "" {
			usedIFNames.Insert(network.InterfaceRequest)
		}
	}

	var savedErr error
	interfacesConfigured := 0
	var netStatus []netdefv1.NetworkStatus

	for _, network := range networkList {
		klog.V(2).InfoS("Secondary Network attached to Pod", "network", network, "Pod", klog.KObj(pod))
		netAttachDef, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(network.Namespace).Get(context.TODO(), network.Name, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to get NetworkAttachmentDefinition", "network", network, "Pod", klog.KObj(pod))
			savedErr = err
			continue
		}

		cniConfig, err := netdefutils.GetCNIConfig(netAttachDef, "")
		if err != nil {
			klog.ErrorS(err, "Failed to parse NetworkAttachmentDefinition", "network", network, "Pod", klog.KObj(pod))
			// NetworkAttachmentDefinition Spec.Config parsing failed. Do not retry.
			continue
		}

		networkConfig, err := validateNetworkConfig(cniConfig)
		if err != nil {
			if networkConfig != nil && networkConfig.Type != cniserver.AntreaCNIType {
				// Ignore non-Antrea CNI type.
				klog.InfoS("Not Antrea CNI type in NetworkAttachmentDefinition, ignoring",
					"NetworkAttachmentDefinition", klog.KObj(netAttachDef), "Pod", klog.KObj(pod))
			} else {
				klog.ErrorS(err, "NetworkConfig validation failed",
					"NetworkAttachmentDefinition", klog.KObj(netAttachDef), "Pod", klog.KObj(pod))
			}
			continue
		}

		if networkConfig.NetworkType == vlanNetworkType && networkConfig.Master != "" {
			if _, ovsErr := pc.ovsBridgeClient.GetOFPort(networkConfig.Master, false); ovsErr == nil {
				klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge", "device", networkConfig.Master)
			} else {
				// Connect a physical interface to OVS bridge.
				err = secondaryutil.ConnectPhyInterfacesToOVSBridge(pc.ovsBridgeClient, []string{networkConfig.Master})
				if err != nil {
					klog.ErrorS(err, "failed to connect physical interface to OVS bridge", "interface", networkConfig.Master)
					continue
				}
			}
			err = pc.ovsBridgeClient.AddTrunksToPort(networkConfig.Master, int32(networkConfig.VLAN))
			if err != nil {
				klog.ErrorS(err, "failed to update port with given VLAN ID in trunks on OVS bridge", "interface", networkConfig.Master, "vlanID", networkConfig.VLAN)
				continue
			}
		}

		var resourceName string
		if networkConfig.NetworkType == sriovNetworkType {
			v, ok := netAttachDef.Annotations[resourceNameAnnotationKey]
			if !ok {
				// This annotation is required for SRIOV devices, otherwise there is
				// no way to make sure that we allocate the "right" type of device.
				err := fmt.Errorf("missing annotation: %s", resourceNameAnnotationKey)
				klog.ErrorS(err, "Invalid NetworkAttachmentDefinition", "NetworkAttachmentDefinition", klog.KObj(netAttachDef))
				// It is probably worth retrying as the NetworkAttachmentDefinition
				// may eventually be updated with the missing annotation.
				savedErr = err
				continue
			}
			resourceName = v
		}

		// Generate a new interface name, if the secondary interface name was not provided in the
		// Pod annotation.
		if network.InterfaceRequest == "" {
			var err error
			if network.InterfaceRequest, err = allocatePodSecondaryIfaceName(usedIFNames); err != nil {
				klog.ErrorS(err, "Cannot generate interface name", "Pod", klog.KObj(pod))
				// Do not return error: no need to requeue.
				continue
			}
		}

		// Get and validate the MAC from annotation, ignore for SR-IOV
		getRequestedMAC := func() (net.HardwareAddr, error) {
			if network.MacRequest == "" {
				return nil, nil // No MAC requested, skip
			}

			if networkConfig.NetworkType == sriovNetworkType {
				klog.InfoS("User-defined MAC address is not supported for SR-IOV networks, ignoring it",
					"MAC", network.MacRequest, "Pod", klog.KObj(pod), "network", network.Name)
				return nil, nil
			}

			if usedIFMAC.Has(network.MacRequest) {
				return nil, fmt.Errorf("duplicate MAC address: %s", network.MacRequest)
			}

			mac, err := net.ParseMAC(network.MacRequest)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC address: %w", err)
			}

			usedIFMAC.Insert(network.MacRequest)
			return mac, nil
		}

		mac, err := getRequestedMAC()
		if err != nil {
			klog.ErrorS(err, "Failed to process requested MAC address", "MAC", network.MacRequest, "Pod", klog.KObj(pod), "network", network.Name)
			// Do not return error: no need to requeue.
			continue
		}

		// Secondary network information retrieved from API server. Proceed to configure secondary interface now.
		res, err := pc.configureSecondaryInterface(pod, network, resourceName, podCNIInfo, networkConfig, mac)
		if err != nil {
			klog.ErrorS(err, "Secondary interface configuration failed",
				"Pod", klog.KObj(pod), "interface", network.InterfaceRequest,
				"networkType", networkConfig.NetworkType)
			savedErr = err
			continue
		}
		status := &netdefv1.NetworkStatus{
			Name:    network.Name,
			Default: false, // Secondary interfaces are not for the default Pod network
		}

		if networkConfig.NetworkType == sriovNetworkType && len(res.Interfaces) > 1 {
			status.DeviceInfo = &netdefv1.DeviceInfo{
				Type: netdefv1.DeviceInfoTypePCI,
				Pci:  &netdefv1.PciDevice{PciAddress: res.Interfaces[1].PciID},
			}
		}

		for _, iface := range res.Interfaces {
			if iface.Sandbox != "" {
				status.Interface = iface.Name
				status.Mac = iface.Mac
			}
		}

		for _, ip := range res.IPs {
			status.IPs = append(status.IPs, ip.Address.IP.String())
		}

		netStatus = append(netStatus, *status)
		interfacesConfigured++
	}

	if savedErr != nil && interfacesConfigured == 0 {
		// As we do not support secondary network update, do not return error to
		// retry, if at least one secondary network is configured.
		return nil, savedErr
	}

	return netStatus, nil
}

func validateNetworkConfig(cniConfig []byte) (*SecondaryNetworkConfig, error) {
	var networkConfig SecondaryNetworkConfig
	if err := json.Unmarshal(cniConfig, &networkConfig); err != nil {
		return nil, fmt.Errorf("invalid CNI configuration: %v", err)
	}
	if !cniserver.IsCNIVersionSupported(networkConfig.CNIVersion) {
		return &networkConfig, fmt.Errorf("unsupported CNI version %s", networkConfig.CNIVersion)
	}
	if networkConfig.Type != cniserver.AntreaCNIType {
		return &networkConfig, fmt.Errorf("not Antrea CNI type '%s'", networkConfig.Type)
	}
	if networkConfig.NetworkType != sriovNetworkType && networkConfig.NetworkType != vlanNetworkType {
		return &networkConfig, fmt.Errorf("secondary network type '%s' not supported", networkConfig.NetworkType)
	}
	if networkConfig.NetworkType == vlanNetworkType {
		if networkConfig.VLAN > vlanIDMax || networkConfig.VLAN < 0 {
			return &networkConfig, fmt.Errorf("invalid VLAN ID %d", networkConfig.VLAN)
		}
		if networkConfig.Master != "" && networkConfig.VLAN == 0 {
			return &networkConfig, fmt.Errorf("VLAN ID must be specified when master interface is set")
		}
	}
	if networkConfig.MTU < 0 {
		return &networkConfig, fmt.Errorf("invalid MTU %d", networkConfig.MTU)
	}
	if networkConfig.IPAM != nil {
		if networkConfig.IPAM.Type != ipam.AntreaIPAMType {
			return &networkConfig, fmt.Errorf("unsupported IPAM type %s", networkConfig.IPAM.Type)
		}
	}

	if networkConfig.MTU == 0 {
		// TODO: use the physical interface MTU as the default.
		networkConfig.MTU = interfaceDefaultMTU
	}
	return &networkConfig, nil
}

func (pc *PodController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.InfoS("Shutting down", "controller", controllerName)
		pc.queue.ShutDown()
	}()
	klog.InfoS("Starting ", "controller", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, pc.podInformer.HasSynced) {
		return
	}

	// Failure of initializeSRIOVSecondaryInterfaceStore() won't stop agent from starting.
	if err := pc.initializeSRIOVSecondaryInterfaceStore(); err != nil {
		klog.ErrorS(err, "Failed to initialize secondary interface store for SR-IOV devices")
		return
	}

	go wait.NonSlidingUntil(pc.cleanUpStaleIPAddresses, 5*time.Minute, stopCh)

	pc.reconcileSecondaryInterfaces()

	for i := 0; i < numWorkers; i++ {
		go wait.Until(pc.Worker, time.Second, stopCh)
	}

	<-stopCh
}

func checkForPodSecondaryNetworkAttachment(pod *corev1.Pod) (string, bool) {
	annotations := pod.GetAnnotations()
	if annotations == nil {
		return "", false
	}
	netObj, netObjExists := annotations[netdefv1.NetworkAttachmentAnnot]
	return netObj, netObjExists && netObj != ""
}

// When a Kubernetes Node reboots and the OVSDB file is not properly restored,
// the primary and secondary OVS ports in OVSDB are lost. Pods may temporarily
// appear as "unknown" and later get recreated on the same Node with new container IDs.
// The cleanup of secondary interfaces during agent restart depends on the InterfaceStores
// being initialized with existing OVS ports. If the OVSDB file is missing, the
// primary InterfaceStore is empty, preventing the secondary InterfaceStore from
// initializing correctly. Consequently, secondary IPs assigned to old Pods (with
// previous container IDs) are not deleted. To resolve this, all IPPool allocations
// must be checked, and any IPs associated with non-existing container IDs should be
// released. Otherwise, stale secondary IPs remain in the IPPool and cannot be reused.
// We run it periodically to cover the case where a Pod is recreated with
// the same name on another Node and has any secondary IP as well.
func (pc *PodController) cleanUpStaleIPAddresses() {
	pools, _ := pc.ipPoolLister.List(labels.Everything())
	for _, ipPool := range pools {
		for _, address := range ipPool.Status.IPAddresses {
			if address.Owner.Pod == nil {
				klog.InfoS("IPAM allocation found with no Pod owner", "IPPool", ipPool.Name)
				continue
			}
			if _, err := pc.podLister.Pods(address.Owner.Pod.Namespace).Get(address.Owner.Pod.Name); err == nil {
				if _, found := pc.interfaceStore.GetContainerInterface(address.Owner.Pod.ContainerID); !found {
					stalePodOwner := address.Owner.Pod
					// Only consider SecondaryNetwork interfaces
					if stalePodOwner.IFName == "" {
						continue
					}
					klog.V(2).InfoS("Releasing stale IPAM allocation", "Pod", klog.KRef(stalePodOwner.Namespace, stalePodOwner.Name), "containerID", stalePodOwner.ContainerID, "interface", stalePodOwner.IFName)
					if err := pc.ipamAllocator.SecondaryNetworkRelease(stalePodOwner); err != nil {
						klog.ErrorS(err, "Error when releasing IPAM allocation",
							"Pod", klog.KRef(stalePodOwner.Namespace, stalePodOwner.Name), "interface", stalePodOwner.IFName)
					}
				}
			}
		}
	}
}

func (pc *PodController) initializeCNICache() {
	knownInterfaces := pc.primaryInterfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, containerConfig := range knownInterfaces {
		config := containerConfig.ContainerInterfaceConfig
		podKey := podKeyGet(config.PodName, config.PodNamespace)
		pc.cniCache.Store(podKey, &podCNIInfo{
			containerID: config.ContainerID,
			netNS:       config.NetNS,
		})
	}
}

// initializeOVSSecondaryInterfaceStore restores secondary interfaceStore for VLAN interfaces when agent restarts.
func (pc *PodController) initializeOVSSecondaryInterfaceStore() error {
	// This is the case when secondary bridge is not configured and no VLAN interface at all.
	if pc.ovsBridgeClient == nil {
		return nil
	}
	ovsPorts, err := pc.ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports for the secondary bridge: %w", err)
	}

	ifaceList := make([]*interfacestore.InterfaceConfig, 0, len(ovsPorts))
	for index := range ovsPorts {
		port := &ovsPorts[index]
		ovsPort := &interfacestore.OVSPortConfig{
			PortUUID: port.UUID,
			OFPort:   port.OFPort,
		}

		interfaceType, ok := port.ExternalIDs[interfacestore.AntreaInterfaceTypeKey]
		if !ok {
			klog.InfoS("Interface type is not set for the secondary bridge", "interfaceName", port.Name)
			continue
		}

		var intf *interfacestore.InterfaceConfig
		switch interfaceType {
		case interfacestore.AntreaContainer:
			intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort)
		default:
			klog.InfoS("Unknown Antrea interface type for the secondary bridge", "type", interfaceType)
			continue
		}
		ifaceList = append(ifaceList, intf)
	}

	pc.interfaceStore.Initialize(ifaceList)
	klog.InfoS("Successfully initialized the secondary bridge interface store")

	return nil
}

// initializeSRIOVSecondaryInterfaceStore restores secondary interfaceStore for SR-IOV interfaces
// when agent restarts. It will get the Pod info from the store of primary interfaces, and check
// the NetworkStatus annotation of a Pod, then restore the SR-IOV interfaces based on the NetworkAttachmentDefinition
// name and device's pci_address in the NetworkStatus.
func (pc *PodController) initializeSRIOVSecondaryInterfaceStore() error {
	knownInterfaces := pc.primaryInterfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, ifconf := range knownInterfaces {
		podNamespace := ifconf.ContainerInterfaceConfig.PodNamespace
		podName := ifconf.ContainerInterfaceConfig.PodName
		podRef := klog.KRef(podNamespace, podName)
		pod, err := pc.podLister.Pods(podNamespace).Get(podName)
		if err != nil {
			klog.ErrorS(err, "Failed to get Pod", "Pod", podRef)
			continue
		}
		_, found := checkForPodSecondaryNetworkAttachment(pod)
		if !found {
			klog.V(2).InfoS("Pod does not have a NetworkAttachmentDefinition", "Pod", podRef)
			continue
		}
		netStatus, err := netdefutils.GetNetworkStatus(pod)
		if err != nil {
			klog.ErrorS(err, "Failed to get NetworkStatus for Pod", "Pod", podRef)
			continue
		}

		cache, err := pc.buildVFDeviceIDListPerPod(podName, podNamespace)
		if err != nil {
			return err
		}

		for _, status := range netStatus {
			if status.DeviceInfo == nil || status.DeviceInfo.Pci == nil {
				continue
			}

			for idx := range cache {
				if cache[idx].vfDeviceID != status.DeviceInfo.Pci.PciAddress {
					continue
				}
				cache[idx].ifName = status.Interface
				// Add the interface to the Secondary interfaceStore.
				containerMAC, _ := net.ParseMAC(status.Mac)
				secondaryInterfaceConfig := interfacestore.NewContainerInterface(
					cache[idx].vfDeviceID,
					ifconf.ContainerInterfaceConfig.ContainerID,
					podName,
					podNamespace,
					status.Interface,
					ifconf.ContainerInterfaceConfig.NetNS,
					containerMAC,
					parseIPs(status.IPs),
					0)
				klog.InfoS("Adding secondary interface to interfaceStore", "Pod", podRef, "interface", status.Interface)
				pc.interfaceStore.AddInterface(secondaryInterfaceConfig)
			}
		}
	}
	klog.InfoS("Successfully initialized the secondary interface store for SR-IOV devices")
	return nil
}

func parseIPs(ips []string) []net.IP {
	containerIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			containerIPs = append(containerIPs, parsedIP)
		} else {
			klog.ErrorS(nil, "Failed to parse IP address", "ip", ip)
		}
	}
	return containerIPs
}

// reconcileSecondaryInterfaces deletes stale secondary interfaces after agent restarts.
func (pc *PodController) reconcileSecondaryInterfaces() {
	var staleInterfaces []*interfacestore.InterfaceConfig
	// secondaryInterfaces is the list of interfaces currently in the secondary local cache.
	secondaryInterfaces := pc.interfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, containerConfig := range secondaryInterfaces {
		_, exists := pc.primaryInterfaceStore.GetContainerInterface(containerConfig.ContainerID)
		if !exists || (containerConfig.OVSPortConfig != nil && containerConfig.OFPort == -1) {
			// Delete an interface when the primary interface has already been deleted,
			// and delete the OVS port when a secondary interface is missing
			// (OFPort == -1).
			// In a normal case, a SR-IOV interface should not be included here, as the
			// primary interface cannot be deleted until the Pod's SR-IOV interfaces are
			// all deleted.
			staleInterfaces = append(staleInterfaces, containerConfig)
		}
	}

	// If there are any stale interfaces, pass them to removeInterfaces()
	if len(staleInterfaces) > 0 {
		if err := pc.removeInterfaces(staleInterfaces); err != nil {
			klog.ErrorS(err, "Failed to remove stale secondary interfaces", "staleInterfaces", staleInterfaces)
		}
	}
}
