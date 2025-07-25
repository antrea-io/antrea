// Copyright 2023 Antrea Authors
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
	"fmt"
	"path"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	// Version v1 of the kubelet API was introduced in K8s v1.20.
	// Using version v1alpha1 instead to support older K8s versions.
	current "github.com/containernetworking/cni/pkg/types/100"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"

	"antrea.io/antrea/pkg/agent/interfacestore"
)

const (
	kubeletPodResourcesPath = "/var/lib/kubelet/pod-resources"
	kubeletSocket           = "kubelet.sock"
	listTimeout             = 10 * time.Second
)

var (
	// getPodContainerDeviceIDsFn is used to retrieve SRIOV device IDs
	// assigned to a specific Pod. It can be overridden by unit tests.
	getPodContainerDeviceIDsFn = getPodContainerDeviceIDs
)

// Structure to associate a unique VF's PCI Address to the Linux ethernet interface.
type podSriovVFDeviceIDInfo struct {
	resourceName string
	vfDeviceID   string
	ifName       string
}

// getPodContainerDeviceIDs returns the device IDs assigned to a Pod's containers.
func getPodContainerDeviceIDs(podName string, podNamespace string) (map[string][]string, error) {
	conn, err := grpc.NewClient(
		"unix:///"+path.Join(kubeletPodResourcesPath, kubeletSocket),
		grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("error getting the gRPC client for Pod resources: %v", err)
	}
	defer conn.Close()

	client := podresourcesv1alpha1.NewPodResourcesListerClient(conn)
	if client == nil {
		return nil, fmt.Errorf("error getting the lister client for Pod resources")
	}

	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()

	podResources, err := client.List(ctx, &podresourcesv1alpha1.ListPodResourcesRequest{})
	if err != nil {
		return nil, fmt.Errorf("error getting the Pod resources: %v %v", podResources, err)
	}

	podDeviceIDs := make(map[string][]string)
	resources := podResources.GetPodResources()
	for _, pr := range resources {
		if pr.Name == podName && pr.Namespace == podNamespace {
			for _, ctr := range pr.Containers {
				for _, dev := range ctr.Devices {
					podDeviceIDs[dev.ResourceName] = append(podDeviceIDs[dev.ResourceName], dev.DeviceIds...)
				}
			}
		}
	}
	klog.V(2).InfoS("Retrieved Pod container device IDs", "pod", klog.KRef(podNamespace, podName), "deviceIDs", podDeviceIDs)
	return podDeviceIDs, nil
}

// buildVFDeviceIDListPerPod is a helper function to build a cache structure with the
// list of all the PCI addresses allocated per Pod based on their resource requests (in Pod spec).
// When there is a request for a VF resource (to associate it for a secondary network interface),
// assignUnusedSriovVFDeviceID will use this cache information to pick up a unique PCI address
// which is still not associated with a network device name.
// NOTE: buildVFDeviceIDListPerPod is called only if a Pod specific VF to Interface mapping cache
// was not build earlier. Sample initial entry per Pod: "{18:01.1,""},{18:01.2,""},{18:01.3,""}"
func (pc *PodController) buildVFDeviceIDListPerPod(podName, podNamespace string) ([]podSriovVFDeviceIDInfo, error) {
	podKey := podKeyGet(podName, podNamespace)
	deviceCache, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		return deviceCache.([]podSriovVFDeviceIDInfo), nil
	}
	deviceIDsByResourceName, err := getPodContainerDeviceIDsFn(podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("getPodContainerDeviceIDs failed: %w", err)
	}
	var vfDeviceIDInfoCache []podSriovVFDeviceIDInfo
	for resourceName, deviceIDs := range deviceIDsByResourceName {
		for _, deviceID := range deviceIDs {
			vfDeviceIDInfoCache = append(vfDeviceIDInfoCache, podSriovVFDeviceIDInfo{
				resourceName: resourceName,
				vfDeviceID:   deviceID,
				ifName:       "", // we will set this field when allocating the device
			})
		}
	}
	pc.vfDeviceIDUsageMap.Store(podKey, vfDeviceIDInfoCache)
	klog.V(2).InfoS("Pod specific SRIOV VF cache created", "Key", podKey)
	return vfDeviceIDInfoCache, nil
}

func (pc *PodController) deleteVFDeviceIDListPerPod(podName, podNamespace string) {
	podKey := podKeyGet(podName, podNamespace)
	_, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		pc.vfDeviceIDUsageMap.Delete(podKey)
		klog.V(2).InfoS("Pod specific SRIOV VF cache cleared", "Key", podKey)
	}
}

func (pc *PodController) releaseSriovVFDeviceID(podName, podNamespace, interfaceName string) {
	podKey := podKeyGet(podName, podNamespace)
	obj, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if !cacheFound {
		return
	}
	cache := obj.([]podSriovVFDeviceIDInfo)
	for idx := range cache {
		if cache[idx].ifName == interfaceName {
			cache[idx].ifName = ""
		}
	}
}

func (pc *PodController) assignSriovVFDeviceID(podName, podNamespace, resourceName, interfaceName string) (string, error) {
	var cache []podSriovVFDeviceIDInfo
	cache, err := pc.buildVFDeviceIDListPerPod(podName, podNamespace)
	if err != nil {
		return "", err
	}

	var unusedCacheEntry *podSriovVFDeviceIDInfo
	for i := range cache {
		entry := &cache[i]
		if entry.resourceName == resourceName {
			if entry.ifName == interfaceName {
				return entry.vfDeviceID, nil
			}
			if entry.ifName == "" && unusedCacheEntry == nil {
				unusedCacheEntry = entry // remember the first match of unused PCI address
			}
		}
	}

	if unusedCacheEntry != nil {
		// Update the cache entry
		unusedCacheEntry.ifName = interfaceName
		return unusedCacheEntry.vfDeviceID, nil
	}
	return "", fmt.Errorf("no available device")
}

// Configure SRIOV VF as a Secondary Network Interface.
func (pc *PodController) configureSriovAsSecondaryInterface(
	pod *corev1.Pod,
	network *netdefv1.NetworkSelectionElement,
	resourceName string,
	podCNIInfo *podCNIInfo,
	mtu int,
	result *current.Result,
) error {
	podSriovVFDeviceID, err := pc.assignSriovVFDeviceID(pod.Name, pod.Namespace, resourceName, network.InterfaceRequest)
	if err != nil {
		return err
	}
	if err = pc.interfaceConfigurator.ConfigureSriovSecondaryInterface(
		pod.Name, pod.Namespace, podCNIInfo.containerID, podCNIInfo.netNS,
		network.InterfaceRequest, mtu, podSriovVFDeviceID, result); err != nil {
		return fmt.Errorf("SRIOV Interface creation failed: %v", err)
	}
	return nil
}

func (pc *PodController) deleteSriovSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error {
	// NOTE: SR-IOV VF interface clean-up will be handled by SR-IOV device plugin. The interface
	// is not deleted here.
	if err := pc.interfaceConfigurator.DeleteSriovSecondaryInterface(interfaceConfig); err != nil {
		return err
	}
	pc.releaseSriovVFDeviceID(interfaceConfig.PodName, interfaceConfig.PodNamespace, interfaceConfig.IFDev)
	return nil
}

// AllowCNIDelete in SecondaryNetwork indicates if a Pod's SR-IOV devices are all detached
// and CNI deletion can be processed to remove the Pod's network namespace.
func (pc *PodController) AllowCNIDelete(podName, podNamespace string) bool {
	podKey := podKeyGet(podName, podNamespace)
	obj, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		cache := obj.([]podSriovVFDeviceIDInfo)
		for _, info := range cache {
			if info.ifName != "" {
				// SR-IOV VF device found.
				return false
			}
		}
	}
	return true
}
