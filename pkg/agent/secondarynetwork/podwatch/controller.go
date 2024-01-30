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

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	cnitypes "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
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
	networkAttachDefAnnotationKey = "k8s.v1.cni.cncf.io/networks"
	cniPath                       = "/opt/cni/bin/"
	startIfaceIndex               = 1
	endIfaceIndex                 = 101

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
	SecondaryNetworkAllocate(podOwner *crdv1a2.PodOwner, networkConfig *cnitypes.NetworkConfig) (*ipam.IPAMResult, error)
	SecondaryNetworkRelease(podOwner *crdv1a2.PodOwner) error
}

type podCNIInfo struct {
	containerID string
	netNS       string
}

type podController struct {
	kubeClient            clientset.Interface
	netAttachDefClient    netdefclient.K8sCniCncfIoV1Interface
	queue                 workqueue.RateLimitingInterface
	podInformer           cache.SharedIndexInformer
	nodeName              string
	podUpdateSubscriber   channel.Subscriber
	ovsBridgeClient       ovsconfig.OVSBridgeClient
	interfaceStore        interfacestore.InterfaceStore
	interfaceConfigurator InterfaceConfigurator
	ipamAllocator         IPAMAllocator
	// Map from "namespace/pod" to podCNIInfo.
	cniCache           sync.Map
	vfDeviceIDUsageMap sync.Map
}

func NewPodController(
	kubeClient clientset.Interface,
	netAttachDefClient netdefclient.K8sCniCncfIoV1Interface,
	podInformer cache.SharedIndexInformer,
	nodeName string,
	podUpdateSubscriber channel.Subscriber,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
) (*podController, error) {
	ifaceStore := interfacestore.NewInterfaceStore()
	interfaceConfigurator, err := cniserver.NewSecondaryInterfaceConfigurator(ovsBridgeClient, ifaceStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create SecondaryInterfaceConfigurator: %v", err)
	}
	pc := podController{
		kubeClient:         kubeClient,
		netAttachDefClient: netAttachDefClient,
		queue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "podcontroller"),
		podInformer:           podInformer,
		nodeName:              nodeName,
		podUpdateSubscriber:   podUpdateSubscriber,
		ovsBridgeClient:       ovsBridgeClient,
		interfaceStore:        ifaceStore,
		interfaceConfigurator: interfaceConfigurator,
		ipamAllocator:         ipam.GetSecondaryNetworkAllocator(),
	}
	podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    pc.enqueuePod,
			DeleteFunc: pc.enqueuePod,
			UpdateFunc: func(old, cur interface{}) { pc.enqueuePod(cur) },
		},
		resyncPeriod,
	)
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

func (pc *podController) enqueuePod(obj interface{}) {
	var err error
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		podDeletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(err, "Unexpected object received:", obj)
			return
		}
		pod, ok := podDeletedState.Obj.(*corev1.Pod)
		if !ok {
			klog.ErrorS(err, "DeletedFinalStateUnknown object is not of type Pod: ", podDeletedState.Obj, pod)
			return
		}
	}
	podKey := podKeyGet(pod.Name, pod.Namespace)
	pc.queue.Add(podKey)
}

// processCNIUpdate will be called when CNIServer publishes a Pod update event.
func (pc *podController) processCNIUpdate(e interface{}) {
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
func (pc *podController) handleAddUpdatePod(pod *corev1.Pod, podCNIInfo *podCNIInfo,
	storedInterfaces []*interfacestore.InterfaceConfig) error {
	if len(storedInterfaces) > 0 {
		// We do not support secondary network update at the moment. Return as long as one
		// secondary interface has been created for the Pod.
		klog.V(1).InfoS("Secondary network already configured on this Pod and update not supported, skipping update",
			"Pod", klog.KObj(pod))
		return nil
	}

	if len(pod.Status.PodIPs) == 0 {
		// Primary network configuration is not complete yet. Return nil here to unqueue the
		// Pod event. Secondary network configuration will be handled with the following Pod
		// update events.
		return nil
	}

	secondaryNetwork, ok := checkForPodSecondaryNetworkAttachement(pod)
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

func (pc *podController) removeInterfaces(interfaces []*interfacestore.InterfaceConfig) error {
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

		podOwner := &crdv1a2.PodOwner{
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

func (pc *podController) syncPod(key string) error {
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
	storedInterfaces := pc.interfaceStore.GetContainerInterfacesByPod(podName, podNamespace)
	if len(storedInterfaces) != 0 {
		// Pod or its primary interface has been deleted. Remove secondary interfaces too.
		if !podExists ||
			// Interfaces created for a previous Pod with the same Namespace/name are
			// not deleted yet. First delete them before processing the new Pod's
			// secondary networks.
			storedInterfaces[0].ContainerID != cniInfo.containerID {
			if err := pc.removeInterfaces(storedInterfaces); err != nil {
				return err
			}
		}
	}

	if !podExists {
		pc.deleteVFDeviceIDListPerPod(podName, podNamespace)
		return nil
	}
	return pc.handleAddUpdatePod(pod, cniInfo, storedInterfaces)
}

func (pc *podController) Worker() {
	for pc.processNextWorkItem() {
	}
}

func (pc *podController) processNextWorkItem() bool {
	obj, quit := pc.queue.Get()
	if quit {
		return false
	}
	defer pc.queue.Done(obj)
	if key, ok := obj.(string); !ok {
		pc.queue.Forget(obj)
	} else if err := pc.syncPod(key); err == nil {
		pc.queue.Forget(key)
	} else {
		pc.queue.AddRateLimited(key)
	}
	return true
}

// Configure Secondary Network Interface.
func (pc *podController) configureSecondaryInterface(
	pod *corev1.Pod,
	network *netdefv1.NetworkSelectionElement,
	podCNIInfo *podCNIInfo,
	networkConfig *SecondaryNetworkConfig) error {
	var ipamResult *ipam.IPAMResult
	var ifConfigErr error
	if networkConfig.IPAM != nil {
		var err error
		podOwner := &crdv1a2.PodOwner{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			ContainerID: podCNIInfo.containerID,
			IFName:      network.InterfaceRequest,
		}
		ipamResult, err = pc.ipamAllocator.SecondaryNetworkAllocate(podOwner, &networkConfig.NetworkConfig)
		if err != nil {
			return fmt.Errorf("secondary network IPAM failed: %v", err)
		}
		defer func() {
			if ifConfigErr != nil {
				// Interface creation failed. Free allocated IP address
				if err := pc.ipamAllocator.SecondaryNetworkRelease(podOwner); err != nil {
					klog.ErrorS(err, "IPAM de-allocation failed: ", err)
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
		ifConfigErr = pc.configureSriovAsSecondaryInterface(pod, network, podCNIInfo, int(networkConfig.MTU), &ipamResult.Result)
	case vlanNetworkType:
		if networkConfig.VLAN > 0 {
			// Let VLAN ID in the CNI network configuration override the IPPool subnet
			// VLAN.
			ipamResult.VLANID = uint16(networkConfig.VLAN)
		}
		ifConfigErr = pc.interfaceConfigurator.ConfigureVLANSecondaryInterface(
			pod.Name, pod.Namespace,
			podCNIInfo.containerID, podCNIInfo.netNS, network.InterfaceRequest,
			int(networkConfig.MTU), ipamResult)
	}
	return ifConfigErr
}

func (pc *podController) configurePodSecondaryNetwork(pod *corev1.Pod, networkList []*netdefv1.NetworkSelectionElement, podCNIInfo *podCNIInfo) error {
	usedIFNames := sets.New[string]()
	for _, network := range networkList {
		if network.InterfaceRequest != "" {
			usedIFNames.Insert(network.InterfaceRequest)
		}
	}

	var savedErr error
	interfacesConfigured := 0
	for _, network := range networkList {
		klog.V(2).InfoS("Secondary Network attached to Pod", "network", network, "Pod", klog.KObj(pod))
		netDefCRD, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(network.Namespace).Get(context.TODO(), network.Name, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to get NetworkAttachmentDefinition",
				"network", network, "Pod", klog.KRef(pod.Namespace, pod.Name))
			savedErr = err
			continue
		}

		cniConfig, err := netdefutils.GetCNIConfig(netDefCRD, "")
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
					"NetworkAttachmentDefinition", klog.KObj(netDefCRD), "Pod", klog.KRef(pod.Namespace, pod.Name))
			} else {
				klog.ErrorS(err, "NetworkConfig validation failed",
					"NetworkAttachmentDefinition", klog.KObj(netDefCRD), "Pod", klog.KRef(pod.Namespace, pod.Name))
			}
			continue
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
		if err = pc.configureSecondaryInterface(pod, network, podCNIInfo, networkConfig); err != nil {
			klog.ErrorS(err, "Secondary interface configuration failed",
				"Pod", klog.KRef(pod.Namespace, pod.Name), "interface", network.InterfaceRequest,
				"networkType", networkConfig.NetworkType)
			savedErr = err
		} else {
			interfacesConfigured++
		}
	}

	if savedErr != nil && interfacesConfigured == 0 {
		// As we do not support secondary network update, do not return error to
		// retry, if at least one secondary network is configured.
		return savedErr
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

func (pc *podController) Run(stopCh <-chan struct{}) {
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

func checkForPodSecondaryNetworkAttachement(pod *corev1.Pod) (string, bool) {
	netObj, netObjExist := pod.GetAnnotations()[networkAttachDefAnnotationKey]
	if netObjExist {
		return netObj, true
	} else {
		return netObj, false
	}
}
