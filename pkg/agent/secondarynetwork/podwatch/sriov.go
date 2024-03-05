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
	"net"
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
	connectionTimeout       = 10 * time.Second
)

var (
	// getPodContainerDeviceIDsFn is used to retrieve SRIOV device IDs
	// assigned to a specific Pod. It can be overridden by unit tests.
	getPodContainerDeviceIDsFn = getPodContainerDeviceIDs
)

type kubeletPodResources struct {
	resources []*podresourcesv1alpha1.PodResources
}

// Structure to associate a unique VF's PCI Address to the Linux ethernet interface.
type podSriovVFDeviceIDInfo struct {
	vfDeviceID string
	ifName     string
}

// getPodContainerDeviceIDs returns the device IDs assigned to a Pod's containers.
func getPodContainerDeviceIDs(podName string, podNamespace string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		path.Join(kubeletPodResourcesPath, kubeletSocket),
		grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (conn net.Conn, e error) {
			return net.Dial("unix", addr)
		}),
	)
	if err != nil {
		return []string{}, fmt.Errorf("error getting the gRPC client for Pod resources: %v", err)
	}
	defer conn.Close()

	client := podresourcesv1alpha1.NewPodResourcesListerClient(conn)
	if client == nil {
		return []string{}, fmt.Errorf("error getting the lister client for Pod resources")
	}

	podResources, err := client.List(ctx, &podresourcesv1alpha1.ListPodResourcesRequest{})
	if err != nil {
		return []string{}, fmt.Errorf("error getting the Pod resources: %v %v", podResources, err)
	}

	var podDeviceIDs []string
	var kpr kubeletPodResources
	kpr.resources = podResources.GetPodResources()
	for _, pr := range kpr.resources {
		if pr.Name == podName && pr.Namespace == podNamespace {
			for _, ctr := range pr.Containers {
				for _, dev := range ctr.Devices {
					podDeviceIDs = append(podDeviceIDs, dev.DeviceIds...)
				}
			}
		}
	}
	klog.V(2).Infof("Pod container device IDs of %s/%s are: %v", podNamespace, podName, podDeviceIDs)
	return podDeviceIDs, nil
}

// buildVFDeviceIDListPerPod is a helper function to build a cache structure with the
// list of all the PCI addresses allocated per Pod based on their resource requests (in Pod spec).
// When there is a request for a VF resource (to associate it for a secondary network interface),
// getUnusedSriovVFDeviceIDPerPod will use this cache information to pick up a unique PCI address
// which is still not associated with a network device name.
// NOTE: buildVFDeviceIDListPerPod is called only if a Pod specific VF to Interface mapping cache
// was not build earlier. Sample initial entry per Pod: "{18:01.1,""},{18:01.2,""},{18:01.3,""}"
func (pc *podController) buildVFDeviceIDListPerPod(podName, podNamespace string) ([]podSriovVFDeviceIDInfo, error) {
	podKey := podKeyGet(podName, podNamespace)
	deviceCache, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		return deviceCache.([]podSriovVFDeviceIDInfo), nil
	}
	podSriovVFDeviceIDs, err := getPodContainerDeviceIDsFn(podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("getPodContainerDeviceIDs failed: %v", err)
	}
	var vfDeviceIDInfoCache []podSriovVFDeviceIDInfo
	for _, pciAddress := range podSriovVFDeviceIDs {
		initSriovVfDeviceID := podSriovVFDeviceIDInfo{vfDeviceID: pciAddress, ifName: ""}
		vfDeviceIDInfoCache = append(vfDeviceIDInfoCache, initSriovVfDeviceID)
	}
	pc.vfDeviceIDUsageMap.Store(podKey, vfDeviceIDInfoCache)
	klog.V(2).InfoS("Pod specific SRIOV VF cache created", "Key", podKey)
	return vfDeviceIDInfoCache, nil
}

func (pc *podController) deleteVFDeviceIDListPerPod(podName, podNamespace string) {
	podKey := podKeyGet(podName, podNamespace)
	_, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if cacheFound {
		pc.vfDeviceIDUsageMap.Delete(podKey)
		klog.V(2).InfoS("Pod specific SRIOV VF cache cleared", "Key", podKey)
	}
	return
}

func (pc *podController) releaseSriovVFDeviceID(podName, podNamespace, interfaceName string) {
	podKey := podKeyGet(podName, podNamespace)
	obj, cacheFound := pc.vfDeviceIDUsageMap.Load(podKey)
	if !cacheFound {
		return
	}
	cache := obj.([]podSriovVFDeviceIDInfo)
	for idx := 0; idx < len(cache); idx++ {
		if cache[idx].ifName == interfaceName {
			cache[idx].ifName = ""
		}
	}
}

func (pc *podController) assignUnusedSriovVFDeviceID(podName, podNamespace, interfaceName string) (string, error) {
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

// Configure SRIOV VF as a Secondary Network Interface.
func (pc *podController) configureSriovAsSecondaryInterface(pod *corev1.Pod, network *netdefv1.NetworkSelectionElement, podCNIInfo *podCNIInfo, mtu int, result *current.Result) error {
	podSriovVFDeviceID, err := pc.assignUnusedSriovVFDeviceID(pod.Name, pod.Namespace, network.InterfaceRequest)
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

func (pc *podController) deleteSriovSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error {
	// NOTE: SR-IOV VF interface clean-up will be handled by SR-IOV device plugin. The interface
	// is not deleted here.
	if err := pc.interfaceConfigurator.DeleteSriovSecondaryInterface(interfaceConfig); err != nil {
		return err
	}
	pc.releaseSriovVFDeviceID(interfaceConfig.PodName, interfaceConfig.PodNamespace, interfaceConfig.IFDev)
	return nil
}
