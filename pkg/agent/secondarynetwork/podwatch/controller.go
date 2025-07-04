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
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	current "github.com/containernetworking/cni/pkg/types/100"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"

	"antrea.io/antrea/v2/pkg/agent/cniserver"
	"antrea.io/antrea/v2/pkg/agent/cniserver/ipam"
	cnitypes "antrea.io/antrea/v2/pkg/agent/cniserver/types"
	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/types"
	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	"antrea.io/antrea/v2/pkg/util/channel"
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

type InterfaceConfigurator interface {
	ConfigureSriovSecondaryInterface(podName, podNamespace, containerID, containerNetNS, containerInterfaceName string, mtu int, podSriovVFDeviceID string, result *current.Result) error
	DeleteSriovSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error
	ConfigureVLANSecondaryInterface(podName, podNamespace, containerID, containerNetNS, containerInterfaceName string, mtu int, ipamResult *ipam.IPAMResult) error
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
) (*PodController, error) {
	ifaceStore := interfacestore.NewInterfaceStore()
	interfaceConfigurator, err := cniserver.NewSecondaryInterfaceConfigurator(ovsBridgeClient, ifaceStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create SecondaryInterfaceConfigurator: %v", err)
	}
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

	// This is the case when secondary bridge is not configured and no VLAN interfaces at all. In this case,
	// we should skip both initializeSecondaryInterfaceStore and reconcileSecondaryInterfaces.
	if ovsBridgeClient != nil {
		if err := pc.initializeSecondaryInterfaceStore(); err != nil {
			return nil, fmt.Errorf("failed to initialize secondary interface store: %w", err)
		}

		if err := pc.reconcileSecondaryInterfaces(); err != nil {
			return nil, fmt.Errorf("failed to restore CNI cache and reconcile secondary interfaces: %w", err)
		}
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
	if len(storedSecondaryInterfaces) > 0 {
		// We do not support secondary network update at the moment. Return as long as one
		// secondary interface has been created for the Pod.
		klog.V(1).InfoS("Secondary network already configured on this Pod and update not supported, skipping update",
			"Pod", klog.KObj(pod))
		return nil
	}
	if len(pod.Status.PodIPs) == 0 {
		// Primary network configuration is not complete yet. Return nil here to dequeue the
		// Pod event. Secondary network configuration will be handled with the following Pod
		// update events.
		return nil
	}

	secondaryNetwork, ok := checkForPodSecondaryNetworkAttachment(pod)
	if !ok {
		// NOTE: We do not handle Pod annotation deletion/update scenario at present.
		klog.V(2).InfoS("Pod does not have a NetworkAttachmentDefinition", "Pod", klog.KObj(pod))
		return nil
	}
	// Parse Pod annotation and proceed with the secondary network configuration.
	networklist, err := netdefutils.ParseNetworkAnnotation(secondaryNetwork, pod.Namespace)
	if err != nil {
		klog.ErrorS(err, "Error when parsing network annotation", "annotation", secondaryNetwork)
		// Do not return an error as a retry is not appropriate.
		// When the annotation is fixed, the Pod will be enqueued again.
		return nil
	}

	return pc.configurePodSecondaryNetwork(pod, networklist, podCNIInfo)
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
		ifConfigErr = pc.configureSriovAsSecondaryInterface(pod, network, resourceName, podCNIInfo, int(networkConfig.MTU), &ipamResult.Result)
	case vlanNetworkType:
		if networkConfig.VLAN > 0 {
			// Let VLAN ID in the CNI network configuration override the IPPool subnet
			// VLAN.
			ipamResult.VLANID = uint16(networkConfig.VLAN)
		}
		ifConfigErr = pc.interfaceConfigurator.ConfigureVLANSecondaryInterface(
			pod.Name, pod.Namespace,
			podCNIInfo.containerID, podCNIInfo.netNS, network.InterfaceRequest,
			networkConfig.MTU, ipamResult)
	}
	return &ipamResult.Result, ifConfigErr
}

func (pc *PodController) configurePodSecondaryNetwork(pod *corev1.Pod, networkList []*netdefv1.NetworkSelectionElement, podCNIInfo *podCNIInfo) error {
	usedIFNames := sets.New[string]()
	for _, network := range networkList {
		if network.InterfaceRequest != "" {
			usedIFNames.Insert(network.InterfaceRequest)
		}
	}

	var savedErr error
	interfacesConfigured := 0
	var netStatus []netdefv1.NetworkStatus
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

	for _, network := range networkList {
		klog.V(2).InfoS("Secondary Network attached to Pod", "network", network, "Pod", klog.KObj(pod))
		netAttachDef, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(network.Namespace).Get(context.TODO(), network.Name, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to get NetworkAttachmentDefinition",
				"network", network, "Pod", klog.KRef(pod.Namespace, pod.Name))
			savedErr = err
			continue
		}

		cniConfig, err := netdefutils.GetCNIConfig(netAttachDef, "")
		if err != nil {
			klog.ErrorS(err, "Failed to parse NetworkAttachmentDefinition",
				"network", network, "Pod", klog.KRef(pod.Namespace, pod.Name))
			// NetworkAttachmentDefinition Spec.Config parsing failed. Do not retry.
			continue
		}

		networkConfig, err := validateNetworkConfig(cniConfig)
		if err != nil {
			if networkConfig != nil && networkConfig.Type != cniserver.AntreaCNIType {
				// Ignore non-Antrea CNI type.
				klog.InfoS("Not Antrea CNI type in NetworkAttachmentDefinition, ignoring",
					"NetworkAttachmentDefinition", klog.KObj(netAttachDef), "Pod", klog.KRef(pod.Namespace, pod.Name))
			} else {
				klog.ErrorS(err, "NetworkConfig validation failed",
					"NetworkAttachmentDefinition", klog.KObj(netAttachDef), "Pod", klog.KRef(pod.Namespace, pod.Name))
			}
			continue
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
				klog.ErrorS(err, "Cannot generate interface name", "Pod", klog.KRef(pod.Namespace, pod.Name))
				// Do not return error: no need to requeue.
				continue
			}
		}

		// Secondary network information retrieved from API server. Proceed to configure secondary interface now.
		res, err := pc.configureSecondaryInterface(pod, network, resourceName, podCNIInfo, networkConfig)
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
		return savedErr
	}

	// Update the Pod's network status annotation
	if netStatus != nil {
		if err := netdefutils.SetNetworkStatus(pc.kubeClient, pod, netStatus); err != nil {
			klog.ErrorS(err, "Pod network status annotation update failed", "Pod", klog.KObj(pod))
		} else {
			klog.V(2).InfoS("Pod network status annotation updated", "Pod", klog.KObj(pod), "NetworkStatus", netStatus)
		}
	}
	return nil
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
	netObj, netObjExist := annotations[netdefv1.NetworkAttachmentAnnot]
	return netObj, netObjExist
}

// initializeSecondaryInterfaceStore restores secondary interfaceStore when agent restarts.
func (pc *PodController) initializeSecondaryInterfaceStore() error {
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

// reconcileSecondaryInterfaces restores cniCache when agent restarts using primary interfaceStore.
func (pc *PodController) reconcileSecondaryInterfaces() error {
	knownInterfaces := pc.primaryInterfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, containerConfig := range knownInterfaces {
		config := containerConfig.ContainerInterfaceConfig
		podKey := podKeyGet(config.PodName, config.PodNamespace)
		pc.cniCache.Store(podKey, &podCNIInfo{
			containerID: config.ContainerID,
			netNS:       config.NetNS,
		})
	}

	var staleInterfaces []*interfacestore.InterfaceConfig
	// secondaryInterfaces is the list of interfaces currently in the secondary local cache.
	secondaryInterfaces := pc.interfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, containerConfig := range secondaryInterfaces {
		_, exists := pc.primaryInterfaceStore.GetContainerInterface(containerConfig.ContainerID)
		if !exists || containerConfig.OFPort == -1 {
			// Delete ports not in the CNI cache.
			staleInterfaces = append(staleInterfaces, containerConfig)
		}
	}

	// If there are any stale interfaces, pass them to removeInterfaces()
	if len(staleInterfaces) > 0 {
		if err := pc.removeInterfaces(staleInterfaces); err != nil {
			klog.ErrorS(err, "Failed to remove stale secondary interfaces", "staleInterfaces", staleInterfaces)
		}
	}

	return nil
}
