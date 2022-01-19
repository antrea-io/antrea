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
	"context"
	"fmt"
	"net"
	"path"
	"time"

	"github.com/containernetworking/cni/pkg/types/current"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	// Version v1 of the Kubelet API was introduced in K8s v1.20.
	// Using version v1alpha1 instead to support older K8s versions.
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"

	"antrea.io/antrea/pkg/agent/util"
)

const (
	kubeletPodResourcesPath = "/var/lib/kubelet/pod-resources"
	kubeletSocket           = "kubelet.sock"
	connectionTimeout       = 10 * time.Second
)

type KubeletPodResources struct {
	resources []*podresourcesv1alpha1.PodResources
}

// GetPodContainerDeviceIDs returns the device IDs assigned to a Pod's containers.
func GetPodContainerDeviceIDs(podName string, podNamespace string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, path.Join(kubeletPodResourcesPath, kubeletSocket),
		grpc.WithInsecure(), grpc.WithContextDialer(func(ctx context.Context, addr string) (conn net.Conn, e error) {
			return util.DialLocalSocket(addr)
		}))
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
	var kpr KubeletPodResources
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

// ConfigureSriovSecondaryInterface adds Secondary Interface support.
// Limitation: only SR-IOV interface is supported as of now.
func (pc *podConfigurator) ConfigureSriovSecondaryInterface(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	podSriovVFDeviceID string,
	result *current.Result,
) error {
	if podSriovVFDeviceID == "" {
		return fmt.Errorf("error getting the Pod SR-IOV VF device ID")
	}

	err := pc.ifConfigurator.configureContainerLink(podName, podNameSpace, containerID, containerNetNS, containerIFDev, mtu, "", podSriovVFDeviceID, result, nil)
	if err != nil {
		return err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	if err = pc.ifConfigurator.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
		return fmt.Errorf("failed to advertise IP address for container %s: %v", containerID, err)
	}

	klog.Infof("Configured interfaces for container %s; hostIface: %+v, containerIface: %+v", containerID, hostIface, containerIface)
	return nil
}
