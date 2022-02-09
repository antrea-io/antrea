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

	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	invoke "github.com/containernetworking/cni/pkg/invoke"
	current "github.com/containernetworking/cni/pkg/types/current"
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
	sriovInterfaceType            = "sriov"
	defaultSecondaryInterfaceName = "eth1"
	start_iface_index             = 1
	end_iface_index               = 11
	max_rand_index                = 25
)

// Set resyncPeriod to 0 to disable resyncing.
const resyncPeriod = 0 * time.Minute

type PodController struct {
	kubeClient         clientset.Interface
	netAttachDefClient netdefclient.K8sCniCncfIoV1Interface
	queue              workqueue.RateLimitingInterface
	podInformer        cache.SharedIndexInformer
	podLister          corelisters.PodLister
	nodeName           string
	podCache           cnipodcache.CNIPodInfoStore
	cniServer          *cniserver.CNIServer
}

func NewPodController(kubeClient clientset.Interface,
	netAttachDefClient netdefclient.K8sCniCncfIoV1Interface,
	podInformer cache.SharedIndexInformer,
	nodeName string,
	podCache cnipodcache.CNIPodInfoStore,
	cniServer *cniserver.CNIServer) *PodController {

	pc := PodController{
		kubeClient:         kubeClient,
		netAttachDefClient: netAttachDefClient,
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "podcontroller"),
		podInformer:        podInformer,
		podLister:          corelisters.NewPodLister(podInformer.GetIndexer()),
		nodeName:           nodeName,
		podCache:           podCache,
		cniServer:          cniServer,
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

func generatePodSecondaryIfaceName(podCNIInfo *cnipodcache.CNIConfigInfo) string {
	// Assign default interface name, if podCNIInfo.NetworkConfig is empty.
	if count := len(podCNIInfo.NetworkConfig); count == 0 {
		return defaultSecondaryInterfaceName
	} else {
		// Generate new interface name (eth1,eth2..eth10) and return to caller.
		for ifaceIndex := start_iface_index; ifaceIndex < end_iface_index; ifaceIndex++ {
			ifName := fmt.Sprintf("%s%d", "eth", ifaceIndex)
			_, exist := podCNIInfo.NetworkConfig[ifName]
			if !exist {
				return ifName
			}
		}
	}
	// Generates random interface name and return. Above execution will try to ensure allocating interface names in order.
	// If none available between eth1 to eth10 (already used per Pod), generate random name with the integer range.
	return string("eth") + strconv.Itoa(rand.IntnRange(end_iface_index, max_rand_index))
}

func removePodAllSecondaryNetwork(podCNIInfo *cnipodcache.CNIConfigInfo) error {
	var cmdArgs *invoke.Args
	// Clean-up IPAM at whereabouts db (etcd or kubernetes API server) for all the secondary networks of the Pod which is getting removed.
	// NOTE: SR-IOV VF interface clean-up, upon Pod delete will be handled by SR-IOV device plugin. Not handled here.
	cmdArgs = &invoke.Args{Command: string("DEL"), ContainerID: podCNIInfo.ContainerID,
		NetNS: podCNIInfo.ContainerNetNS, Path: cniPath}
	// example: podCNIInfo.NetworkConfig = {"eth1": net1-cniconfig, "eth2": net2-cniconfig}
	for secNetInstIface, secNetInstConfig := range podCNIInfo.NetworkConfig {
		cmdArgs.IfName = secNetInstIface
		// Do DelIPAMSubnetAddress on network config (secNetInstConfig) and command argument (updated with interface name).
		err := ipam.DelIPAMSubnetAddress(secNetInstConfig, cmdArgs)
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
		klog.InfoS("Secondary network already configured on this Pod. Annotation update not supported.", klog.KObj(pod))
		return nil
	}
	// Parse Pod annotation and proceed with the secondary network configuration.
	networklist, err := parsePodSecondaryNetworkAnnotation(secondaryNetwork)
	if err != nil {
		// Return error to requeue and retry.
		return err
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
func (pc *PodController) configureSriovAsSecondaryInterface(pod *corev1.Pod, netinfo *SecondaryNetworkObject, containerInfo *cnipodcache.CNIConfigInfo, result *current.Result) error {
	podSriovVFDeviceID, err := cniserver.GetPodContainerDeviceIDs(pod.Name, pod.Namespace)
	if err != nil {
		return fmt.Errorf("GetPodContainerDeviceIDs failed: %v", err)
	}

	if err = pc.cniServer.GetPodConfigurator().ConfigureSriovSecondaryInterface(
		containerInfo.PodName,
		containerInfo.PodNameSpace,
		containerInfo.ContainerID,
		containerInfo.ContainerNetNS,
		netinfo.InterfaceName,
		containerInfo.MTU,
		podSriovVFDeviceID[0],
		result,
	); err != nil {
		return fmt.Errorf("SRIOV Interface creation failed: %v", err)
	}
	return nil
}

// Configure Secondary Network Interface.
func (pc *PodController) configureSecondaryInterface(pod *corev1.Pod, netinfo *SecondaryNetworkObject, podCNIInfo *cnipodcache.CNIConfigInfo, cniconfig []byte) error {
	var err error
	var ipamerr error
	var ipamResult *current.Result
	var cmdArgs *invoke.Args
	// Generate and assign new interface name, If secondary interface name was not provided in Pod annotation.
	if len(netinfo.InterfaceName) == 0 {
		netinfo.InterfaceName = generatePodSecondaryIfaceName(podCNIInfo)
	}
	if netinfo.InterfaceType == sriovInterfaceType {
		cmdArgs = &invoke.Args{Command: string("ADD"), ContainerID: podCNIInfo.ContainerID,
			NetNS: podCNIInfo.ContainerNetNS, IfName: netinfo.InterfaceName,
			Path: cniPath}
		ipamResult, err = ipam.GetIPAMSubnetAddress(cniconfig, cmdArgs)
		if err != nil {
			return errors.New("secondary network IPAM failed")
		}
		result := &current.Result{CNIVersion: podCNIInfo.CNIVersion}
		result.IPs = ipamResult.IPs
		result.Routes = ipamResult.Routes
		// Set result.Interface to container interface.
		for _, ip := range result.IPs {
			ip.Interface = current.Int(1)
		}
		// Configure SRIOV as a secondary network interface
		if err = pc.configureSriovAsSecondaryInterface(pod, netinfo, podCNIInfo, result); err != nil {
			// SRIOV interface creation failed. Free allocated IP address
			if ipamerr = ipam.DelIPAMSubnetAddress(cniconfig, cmdArgs); ipamerr != nil {
				klog.ErrorS(err, "IPAM de-allocation failed: ", ipamerr)
			}
			return err
		}
		// Update Pod CNI cache with the network config which was successfully configured.
		if podCNIInfo.NetworkConfig == nil {
			podCNIInfo.NetworkConfig = make(map[string][]byte)
		}
		podCNIInfo.NetworkConfig[netinfo.InterfaceName] = cniconfig
	} else {
		klog.ErrorS(err, "InterfaceType not supported for Pod ", klog.KObj(pod))
	}
	return nil
}

func (pc *PodController) configureSecondaryNetwork(pod *corev1.Pod, networklist []*SecondaryNetworkObject, podCNIInfo *cnipodcache.CNIConfigInfo) error {

	for _, netinfo := range networklist {
		klog.InfoS("Secondary Network Information:", netinfo)
		if len(netinfo.NetworkName) > 0 {
			netDefCRD, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(pod.Namespace).Get(context.TODO(), netinfo.NetworkName, metav1.GetOptions{})
			if err != nil {
				// NetworkAttachmentDefinition not found at this time. Return error to re-queue and re-try.
				return fmt.Errorf("NetworkAttachmentDefinitions.Getfailed: %v", err)
			}
			cniconfig, err := netdefutils.GetCNIConfig(netDefCRD, "")
			if err != nil {
				// NetworkAttachmentDefinition Spec.Config parsing failed. return error to re-queue and re-try.
				return fmt.Errorf("net-attach-def: CNI config spec read error: %v", err)
			}
			// secondary network information retrieved from API server. Proceed to configure secondary interface now.
			if err = pc.configureSecondaryInterface(pod, netinfo, podCNIInfo, cniconfig); err != nil {
				// Secondary interface configuration failed. return error to re-queue and re-try.
				return fmt.Errorf("secondary interface configuration failed: %v", err)
			}
		}
	}
	return nil
}

func (pc *PodController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.InfoS("Shutting down", controllerName)
		pc.queue.ShutDown()
	}()
	klog.InfoS("Starting ", controllerName)
	go pc.podInformer.Run(stopCh)
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

func parsePodSecondaryNetworkAnnotation(netObj string) ([]*SecondaryNetworkObject, error) {
	var secNetwork []*SecondaryNetworkObject
	if strings.IndexAny(netObj, "[{\"") >= 0 {
		if err := json.Unmarshal([]byte(netObj), &secNetwork); err != nil {
			return nil, fmt.Errorf("parsePodSecondaryNetworkAnnotation: failed to parse Pod nnotation JSON format %v", err)
		}
	} else {
		// Comma-delimited list of network attachment object names
		for _, item := range strings.Split(netObj, ",") {
			// Remove leading and trailing whitespace.
			item = strings.TrimSpace(item)
			secNetwork = append(secNetwork, &SecondaryNetworkObject{
				NetworkName: item,
			})
		}
	}
	return secNetwork, nil
}
