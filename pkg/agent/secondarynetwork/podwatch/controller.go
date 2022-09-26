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
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	invoke "github.com/containernetworking/cni/pkg/invoke"
	current "github.com/containernetworking/cni/pkg/types/current"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"

	cniserver "antrea.io/antrea/pkg/agent/cniserver"
	cnipodcache "antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	ipam "antrea.io/antrea/pkg/agent/secondarynetwork/ipam"
)

const (
	controllerName = "SecondaryNetworkController"
	minRetryDelay  = 2 * time.Second
	maxRetryDelay  = 120 * time.Second
	numWorkers     = 4
)

const (
	networkAttachDefAnnotationKey = "k8s.v1.cni.cncf.io/networks"
	cniPath                       = "/opt/cni/bin/"
	defaultSecondaryInterfaceName = "eth1"
	startIfaceIndex               = 1
	endIfaceIndex                 = 101
)

// Set resyncPeriod to 0 to disable resyncing.
const resyncPeriod = 0 * time.Minute

var (
	// ipamDelegator is used to request IP addresses for secondary network
	// interfaces. It can be overridden by unit tests.
	ipamDelegator ipam.IPAMDelegator = ipam.NewIPAMDelegator()
	// getPodContainerDeviceIDs is used to retrieve SRIOV device IDs
	// assigned to a specific Pod. It can be overridden by unit tests.
	getPodContainerDeviceIDs = cniserver.GetPodContainerDeviceIDs
)

// Structure to associate a unique VF's PCI Address to the Linux ethernet interface.
type podSriovVFDeviceIDInfo struct {
	vfDeviceID string
	ifName     string
}

type InterfaceConfigurator interface {
	ConfigureSriovSecondaryInterface(podName string, podNameSpace string, containerID string, containerNetNS string, containerIFDev string, mtu int, podSriovVFDeviceID string, result *current.Result) error
}

type PodController struct {
	kubeClient            clientset.Interface
	netAttachDefClient    netdefclient.K8sCniCncfIoV1Interface
	queue                 workqueue.RateLimitingInterface
	podInformer           cache.SharedIndexInformer
	nodeName              string
	podCache              cnipodcache.CNIPodInfoStore
	interfaceConfigurator InterfaceConfigurator
	vfDeviceIDUsageMap    sync.Map
}

func NewPodController(
	kubeClient clientset.Interface,
	netAttachDefClient netdefclient.K8sCniCncfIoV1Interface,
	podInformer cache.SharedIndexInformer,
	nodeName string,
	podCache cnipodcache.CNIPodInfoStore,
	interfaceConfigurator InterfaceConfigurator,
) *PodController {
	pc := PodController{
		kubeClient:            kubeClient,
		netAttachDefClient:    netAttachDefClient,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "podcontroller"),
		podInformer:           podInformer,
		nodeName:              nodeName,
		podCache:              podCache,
		interfaceConfigurator: interfaceConfigurator,
	}
	podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    pc.enqueuePod,
			DeleteFunc: pc.enqueuePod,
			UpdateFunc: func(old, cur interface{}) { pc.enqueuePod(cur) },
		},
		resyncPeriod,
	)
	return &pc
}

func podKeyGet(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

// buildVFDeviceIDListPerPod is a helper function to build a cache structure with the
// list of all the PCI addresses allocated per Pod based on their resource requests (in Pod spec).
// When there is a request for a VF resource (to associate it for a secondary network interface),
// getUnusedSriovVFDeviceIDPerPod will use this cache information to pick up a unique PCI address
// which is still not associated with a network device name.
// NOTE: buildVFDeviceIDListPerPod is called only if a Pod specific VF to Interface mapping cache
// was not build earlier. Sample initial entry per Pod: "{18:01.1,""},{18:01.2,""},{18:01.3,""}"
func (pc *PodController) buildVFDeviceIDListPerPod(podName, podNamespace string) ([]podSriovVFDeviceIDInfo, error) {
	podKey := podNamespace + "/" + podName
	deviceCache, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		return deviceCache.([]podSriovVFDeviceIDInfo), nil
	}
	podSriovVFDeviceIDs, err := getPodContainerDeviceIDs(podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("getPodContainerDeviceIDs failed: %v", err)
	}
	var vfDeviceIDInfoCache []podSriovVFDeviceIDInfo
	for _, pciAddress := range podSriovVFDeviceIDs {
		initSriovVfDeviceID := podSriovVFDeviceIDInfo{vfDeviceID: pciAddress, ifName: ""}
		vfDeviceIDInfoCache = append(vfDeviceIDInfoCache, initSriovVfDeviceID)
	}
	pc.vfDeviceIDUsageMap.Store(podKey, vfDeviceIDInfoCache)
	return vfDeviceIDInfoCache, nil
}

func (pc *PodController) assignUnusedSriovVFDeviceIDPerPod(podName, podNamespace, interfaceName string) (string, error) {
	var cache []podSriovVFDeviceIDInfo
	cache, err := pc.buildVFDeviceIDListPerPod(podName, podNamespace)
	if err != nil {
		return "", err
	}
	for idx := 0; idx < len(cache); idx++ {
		if cache[idx].ifName == "" {
			// Unused PCI address found. Associate PCI address to the interface.
			cache[idx].ifName = interfaceName
			return cache[idx].vfDeviceID, nil
		}
	}
	return "", err
}

func generatePodSecondaryIfaceName(podCNIInfo *cnipodcache.CNIConfigInfo) (string, error) {
	// Assign default interface name, if podCNIInfo.NetworkConfig is empty.
	if count := len(podCNIInfo.NetworkConfig); count == 0 {
		return defaultSecondaryInterfaceName, nil
	} else {
		// Generate new interface name (eth1,eth2..eth100) and return to caller.
		for ifaceIndex := startIfaceIndex; ifaceIndex < endIfaceIndex; ifaceIndex++ {
			ifName := fmt.Sprintf("%s%d", "eth", ifaceIndex)
			_, exist := podCNIInfo.NetworkConfig[ifName]
			if !exist {
				return ifName, nil
			}
		}
	}
	return "", fmt.Errorf("no more interface names")
}

func whereaboutsArgsBuilder(cmd string, interfaceName string, podCNIInfo *cnipodcache.CNIConfigInfo) *invoke.Args {
	// PluginArgs added to provide additional arguments required for whereabouts v0.5.1 and above.
	return &invoke.Args{Command: cmd, ContainerID: podCNIInfo.ContainerID,
		NetNS: podCNIInfo.ContainerNetNS, IfName: interfaceName,
		Path: cniPath, PluginArgs: [][2]string{
			{"K8S_POD_NAME", podCNIInfo.PodName},
			{"K8S_POD_NAMESPACE", podCNIInfo.PodNameSpace},
			{"K8S_POD_INFRA_CONTAINER_ID", podCNIInfo.ContainerID},
		}}

}

func removePodAllSecondaryNetwork(podCNIInfo *cnipodcache.CNIConfigInfo) error {
	var cmdArgs *invoke.Args
	// Clean-up IPAM at whereabouts db (etcd or kubernetes API server) for all the secondary networks of the Pod which is getting removed.
	// PluginArgs added to provide additional arguments required for whereabouts v0.5.1 and above.
	// NOTE: SR-IOV VF interface clean-up, upon Pod delete will be handled by SR-IOV device plugin. Not handled here.
	cmdArgs = whereaboutsArgsBuilder("DEL", "", podCNIInfo)
	// example: podCNIInfo.NetworkConfig = {"eth1": net1-cniconfig, "eth2": net2-cniconfig}
	for secNetInstIface, secNetInstConfig := range podCNIInfo.NetworkConfig {
		cmdArgs.IfName = secNetInstIface
		// Do DelIPAMSubnetAddress on network config (secNetInstConfig) and command argument (updated with interface name).
		err := ipamDelegator.DelIPAMSubnetAddress(secNetInstConfig, cmdArgs)
		if err != nil {
			return fmt.Errorf("Failed to clean-up whereabouts IPAM %v", err)
		}
		// Delete map entry for secNetInstIface, secNetInstConfig
		delete(podCNIInfo.NetworkConfig, secNetInstIface)
	}
	return nil
}

func (pc *PodController) enqueuePod(obj interface{}) {
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
	podKey := podKeyGet(pod)
	pc.queue.Add(podKey)
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (pc *PodController) handleAddUpdatePod(obj interface{}) error {
	var err error
	var podCNIInfo *cnipodcache.CNIConfigInfo
	pod := obj.(*corev1.Pod)
	if len(pod.Status.PodIPs) == 0 {
		// Primary network configuration is not complete yet.
		// Note: Return nil here to unqueue Pod add event. Secondary network configuration will be handled with Pod update event.
		return nil
	}
	secondaryNetwork, ok := checkForPodSecondaryNetworkAttachement(pod)
	if !ok {
		// NOTE: We do not handle Pod annotation deletion/update scenario at present.
		klog.InfoS("Pod does not have a NetworkAttachmentDefinition", "Pod", klog.KObj(pod))
		return nil
	}
	// Retrieve Pod specific cache entry which has "PodCNIDeleted = false"
	if podCNIInfo = pc.podCache.GetValidCNIConfigInfoPerPod(pod.Name, pod.Namespace); podCNIInfo == nil {
		return nil
	}
	// Valid cache entry retrieved from cache and we received a Pod add or update event.
	// Avoid processing Pod annotation, if we already have at least one secondary network successfully configured on this Pod.
	// We do not support/handle Annotation updates yet.
	if len(podCNIInfo.NetworkConfig) > 0 {
		klog.InfoS("Secondary network already configured on this Pod and annotation update not supported, skipping update", "pod", klog.KObj(pod))
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

	err = pc.configureSecondaryNetwork(pod, networklist, podCNIInfo)
	// We do not return error to retry, if at least one secondary network is configured.
	if (err != nil) && (len(podCNIInfo.NetworkConfig) == 0) {
		// Return error to requeue and retry.
		return err
	}
	return nil
}

func (pc *PodController) handleRemovePod(key string) error {
	var err error
	pod := strings.Split(key, "/")
	// Read the CNI info (stored during Pod creation by cniserver) from cache.
	// Delete CNI info shared in cache for a specific Pod which is getting removed/deleted.
	podCNIInfo := pc.podCache.GetAllCNIConfigInfoPerPod(pod[1], pod[0])
	for _, containerInfo := range podCNIInfo {
		// Release IPAM of all the secondary interfaces and delete CNI cache.
		if err = removePodAllSecondaryNetwork(containerInfo); err != nil {
			// Return error to requeue pod delete.
			return err
		} else {
			// Delete cache entry from podCNIInfo.
			pc.podCache.DeleteCNIConfigInfo(containerInfo)
		}
	}
	return nil
}

func (pc *PodController) syncPod(key string) error {
	obj, exists, err := pc.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	} else if exists {
		return pc.handleAddUpdatePod(obj)
	} else {
		return pc.handleRemovePod(key)
	}
}

func (pc *PodController) Worker() {
	for pc.processNextWorkItem() {
	}
}

func (pc *PodController) processNextWorkItem() bool {
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

// Configure SRIOV VF as a Secondary Network Interface.
func (pc *PodController) configureSriovAsSecondaryInterface(pod *corev1.Pod, network *netdefv1.NetworkSelectionElement, containerInfo *cnipodcache.CNIConfigInfo, result *current.Result) error {
	podSriovVFDeviceID, err := pc.assignUnusedSriovVFDeviceIDPerPod(pod.Name, pod.Namespace, network.InterfaceRequest)
	if err != nil {
		return fmt.Errorf("getPodContainerDeviceIDs failed: %v", err)
	}

	if err = pc.interfaceConfigurator.ConfigureSriovSecondaryInterface(
		containerInfo.PodName,
		containerInfo.PodNameSpace,
		containerInfo.ContainerID,
		containerInfo.ContainerNetNS,
		network.InterfaceRequest,
		containerInfo.MTU,
		podSriovVFDeviceID,
		result,
	); err != nil {
		return fmt.Errorf("SRIOV Interface creation failed: %v", err)
	}
	return nil
}

// Configure Secondary Network Interface.
func (pc *PodController) configureSecondaryInterface(pod *corev1.Pod, network *netdefv1.NetworkSelectionElement, podCNIInfo *cnipodcache.CNIConfigInfo, cniConfig []byte) error {
	// Generate and assign new interface name, If secondary interface name was not provided in Pod annotation.
	if len(network.InterfaceRequest) == 0 {
		var err error
		if network.InterfaceRequest, err = generatePodSecondaryIfaceName(podCNIInfo); err != nil {
			klog.ErrorS(err, "Cannot generate interface name", "Pod", klog.KObj(pod))
			// do not return error: no need to requeue
			return nil
		}
	}
	// PluginArgs added to provide additional arguments required for whereabouts v0.5.1 and above.
	cmdArgs := whereaboutsArgsBuilder("ADD", network.InterfaceRequest, podCNIInfo)
	ipamResult, err := ipamDelegator.GetIPAMSubnetAddress(cniConfig, cmdArgs)
	if err != nil {
		return fmt.Errorf("secondary network IPAM failed: %v", err)
	}
	result := &current.Result{CNIVersion: podCNIInfo.CNIVersion}
	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes
	// Set result.Interface to container interface.
	for _, ip := range result.IPs {
		ip.Interface = current.Int(1)
	}
	// Configure SRIOV as a secondary network interface
	if err := pc.configureSriovAsSecondaryInterface(pod, network, podCNIInfo, result); err != nil {
		// SRIOV interface creation failed. Free allocated IP address
		if err := ipamDelegator.DelIPAMSubnetAddress(cniConfig, cmdArgs); err != nil {
			klog.ErrorS(err, "IPAM de-allocation failed: ", err)
		}
		return err
	}
	// Update Pod CNI cache with the network config which was successfully configured.
	if podCNIInfo.NetworkConfig == nil {
		podCNIInfo.NetworkConfig = make(map[string][]byte)
	}
	podCNIInfo.NetworkConfig[network.InterfaceRequest] = cniConfig
	return nil
}

func (pc *PodController) configureSecondaryNetwork(pod *corev1.Pod, networklist []*netdefv1.NetworkSelectionElement, podCNIInfo *cnipodcache.CNIConfigInfo) error {
	for _, network := range networklist {
		klog.InfoS("Secondary Network attached to Pod", "network", network, "Pod", klog.KObj(pod))
		netDefCRD, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(network.Namespace).Get(context.TODO(), network.Name, metav1.GetOptions{})
		if err != nil {
			// NetworkAttachmentDefinition not found at this time. Return error to re-queue and re-try.
			return fmt.Errorf("NetworkAttachmentDefinition Get failed: %v", err)
		}
		cniConfig, err := netdefutils.GetCNIConfig(netDefCRD, "")
		if err != nil {
			// NetworkAttachmentDefinition Spec.Config parsing failed. return error to re-queue and re-try.
			return fmt.Errorf("net-attach-def: CNI config spec read error: %v", err)
		}
		var networkConfig SecondaryNetworkConfig
		if err := json.Unmarshal(cniConfig, &networkConfig); err != nil {
			return fmt.Errorf("invalid NetworkAttachmentDefinition: %v", err)
		}
		if networkConfig.Type != "antrea" {
			// note that at the moment, even if the type is updated, we will not process
			// the request again.
			klog.InfoS("NetworkAttachmentDefinition is not of type 'antrea', ignoring", "NetworkAttachmentDefinition", klog.KObj(netDefCRD))
			continue
		}
		if networkConfig.NetworkType != sriovNetworkType {
			// same as above, if updated, we will not process the request again.
			klog.ErrorS(err, "NetworkType not supported for Pod", "NetworkAttachmentDefinition", klog.KObj(netDefCRD), "Pod", klog.KObj(pod))
			continue
		}
		// secondary network information retrieved from API server. Proceed to configure secondary interface now.
		if err = pc.configureSecondaryInterface(pod, network, podCNIInfo, cniConfig); err != nil {
			// Secondary interface configuration failed. return error to re-queue and re-try.
			return fmt.Errorf("secondary interface configuration failed: %v", err)
		}
	}
	return nil
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

func checkForPodSecondaryNetworkAttachement(pod *corev1.Pod) (string, bool) {
	netObj, netObjExist := pod.GetAnnotations()[networkAttachDefAnnotationKey]
	if netObjExist {
		return netObj, true
	} else {
		return netObj, false
	}
}
