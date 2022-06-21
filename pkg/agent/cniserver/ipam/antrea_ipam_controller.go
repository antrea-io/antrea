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

package ipam

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/informers/externalversions"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	annotation "antrea.io/antrea/pkg/ipam"
	"antrea.io/antrea/pkg/ipam/poolallocator"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "AntreaIPAMController"
	// Pod index name for IPPool cache.
	podIndex = "pod"
)

// Antrea IPAM Controller maintains map of Namespace annotations using
// Namespace informer. In future, which Antrea IPAM support expands,
// this controller can be used to store annotations for other objects,
// such as Statefulsets.
type AntreaIPAMController struct {
	crdClient         clientsetversioned.Interface
	ipPoolInformer    crdinformers.IPPoolInformer
	ipPoolLister      crdlisters.IPPoolLister
	namespaceInformer coreinformers.NamespaceInformer
	namespaceLister   corelisters.NamespaceLister
	podInformer       cache.SharedIndexInformer
	podLister         corelisters.PodLister
}

func podIndexFunc(obj interface{}) ([]string, error) {
	ipPool, ok := obj.(*crdv1a2.IPPool)
	if !ok {
		return nil, fmt.Errorf("obj is not IPPool: %+v", obj)
	}
	podNames := sets.NewString()
	for _, ipAddress := range ipPool.Status.IPAddresses {
		if ipAddress.Owner.Pod != nil {
			podNames.Insert(k8s.NamespacedName(ipAddress.Owner.Pod.Namespace, ipAddress.Owner.Pod.Name))
		}
	}
	return podNames.UnsortedList(), nil
}

func InitializeAntreaIPAMController(crdClient clientsetversioned.Interface,
	informerFactory informers.SharedInformerFactory,
	crdInformerFactory externalversions.SharedInformerFactory,
	podInformer cache.SharedIndexInformer, ipamAnnotations bool) (*AntreaIPAMController, error) {
	// Order of init causes antreaIPAMDriver to be initialized first
	// After controller is initialized by agent init, we need to make it
	// know to the driver
	if antreaIPAMDriver == nil {
		return nil, fmt.Errorf("Antrea IPAM driver failed to initialize")
	}

	var antreaIPAMController *AntreaIPAMController
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	ipPoolInformer.Informer().AddIndexers(cache.Indexers{podIndex: podIndexFunc})

	// Create podInformer/Lister and namespaceInformer/Lister if need to read the AntreaIPAM
	// annotation on Pods and Namespaces.
	if ipamAnnotations {
		namespaceInformer := informerFactory.Core().V1().Namespaces()
		antreaIPAMController = &AntreaIPAMController{
			crdClient:         crdClient,
			ipPoolInformer:    ipPoolInformer,
			ipPoolLister:      ipPoolInformer.Lister(),
			namespaceInformer: namespaceInformer,
			namespaceLister:   namespaceInformer.Lister(),
			podInformer:       podInformer,
			podLister:         corelisters.NewPodLister(podInformer.GetIndexer()),
		}
	} else {
		antreaIPAMController = &AntreaIPAMController{
			crdClient:      crdClient,
			ipPoolInformer: ipPoolInformer,
			ipPoolLister:   ipPoolInformer.Lister(),
		}
	}
	return antreaIPAMController, nil
}

// Run starts to watch and process Namespace updates for the Node where Antrea Agent
// is running, and maintain a mapping between Namespace name and IPAM annotations.
func (c *AntreaIPAMController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.V(2).InfoS("Shutting down", "controller", controllerName)
	}()

	klog.InfoS("Starting", "controller", controllerName)
	cacheSyncs := []cache.InformerSynced{c.ipPoolInformer.Informer().HasSynced}
	if c.podInformer != nil && c.namespaceInformer != nil {
		cacheSyncs = append(cacheSyncs, c.podInformer.HasSynced, c.namespaceInformer.Informer().HasSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}
	antreaIPAMDriver.setController(c)

	<-stopCh
}

// Look up IPPools from the Pod annotation.
func (c *AntreaIPAMController) getIPPoolsByPod(namespace, name string) ([]string, []net.IP, *crdv1a2.IPAddressOwner, error) {
	var ips []net.IP
	var reservedOwner *crdv1a2.IPAddressOwner
	pod, err := c.podLister.Pods(namespace).Get(name)
	if err != nil {
		return nil, nil, nil, err
	}

	annotations, exists := pod.Annotations[annotation.AntreaIPAMAnnotationKey]
	if !exists {
		// Find IPPool by Namespace
		ns, err := c.namespaceLister.Get(namespace)
		if err != nil {
			return nil, nil, nil, nil
		}
		annotations, exists = ns.Annotations[annotation.AntreaIPAMAnnotationKey]
		if !exists {
			return nil, nil, nil, nil
		}
	}

	// Collect specified IPs if exist
	ipStrings, _ := pod.Annotations[annotation.AntreaIPAMPodIPAnnotationKey]
	ipStrings = strings.ReplaceAll(ipStrings, " ", "")
	var ipErr error
	if ipStrings != "" {
		splittedIPStrings := strings.Split(ipStrings, annotation.AntreaIPAMAnnotationDelimiter)
		for _, ipString := range splittedIPStrings {
			ip := net.ParseIP(ipString)
			if ipString != "" && ip == nil {
				ipErr = fmt.Errorf("invalid IP annotation %s", ipStrings)
				ips = nil
				break
			}
			ips = append(ips, ip)
		}
	}

ownerReferenceLoop:
	for _, ownerReference := range pod.OwnerReferences {
		if ownerReference.Controller != nil && *ownerReference.Controller == true {
			switch ownerReference.Kind {
			case "StatefulSet":
				// Parse StatefulSet name/index from Pod name
				statefulSetName, index, err := k8s.ParseStatefulSetName(name)
				if err != nil {
					// This should not occur unless user creates an invalid Pod manually
					klog.Warningf("Invalid StatefulSet name: %s", name)
					break ownerReferenceLoop
				}
				reservedOwner = &crdv1a2.IPAddressOwner{StatefulSet: &crdv1a2.StatefulSetOwner{
					Name:      statefulSetName,
					Namespace: namespace,
					Index:     index,
				}}
				break ownerReferenceLoop
			}
		}
	}

	return strings.Split(annotations, annotation.AntreaIPAMAnnotationDelimiter), ips, reservedOwner, ipErr
}

// Look up IPPools from the Pod annotation.
func (c *AntreaIPAMController) getPoolAllocatorByPod(namespace, podName string) (mineType, *poolallocator.IPPoolAllocator, []net.IP, *crdv1a2.IPAddressOwner, error) {
	poolNames, ips, reservedOwner, err := c.getIPPoolsByPod(namespace, podName)
	if err != nil {
		return mineUnknown, nil, nil, nil, err
	} else if len(poolNames) == 0 {
		return mineFalse, nil, nil, nil, nil
	}

	var allocator *poolallocator.IPPoolAllocator
	for _, p := range poolNames {
		allocator, err = poolallocator.NewIPPoolAllocator(p, c.crdClient, c.ipPoolLister)
		if err != nil {
			if !errors.IsNotFound(err) {
				err = fmt.Errorf("failed to get IPPool %s: %v", p, err)
				break
			}
			klog.InfoS("IPPool not found", "pool", p)
			err = nil
		} else if allocator.IPVersion == crdv1a2.IPv4 {
			// Support IPv6 / dual stack in future.
			break
		}
	}
	if err == nil && allocator == nil {
		err = fmt.Errorf("no valid IPPool found")
	}

	return mineTrue, allocator, ips, reservedOwner, err
}

// Look up IPPools by matching PodOwnder.
func (c *AntreaIPAMController) getPoolAllocatorsByOwner(podOwner *crdv1a2.PodOwner) ([]*poolallocator.IPPoolAllocator, error) {
	var allocators []*poolallocator.IPPoolAllocator
	ipPools, _ := c.ipPoolInformer.Informer().GetIndexer().ByIndex(podIndex,
		k8s.NamespacedName(podOwner.Namespace, podOwner.Name))
	for _, item := range ipPools {
		ipPool := item.(*crdv1a2.IPPool)
		for _, ipAddress := range ipPool.Status.IPAddresses {
			savedPod := ipAddress.Owner.Pod
			if savedPod != nil && savedPod.ContainerID == podOwner.ContainerID && savedPod.IFName == podOwner.IFName {
				allocator, err := poolallocator.NewIPPoolAllocator(ipPool.Name, c.crdClient, c.ipPoolLister)
				if err != nil {
					return nil, err
				}
				allocators = append(allocators, allocator)
			}
		}
	}
	return allocators, nil
}

func (c *AntreaIPAMController) getPoolAllocatorByName(poolName string) (*poolallocator.IPPoolAllocator, error) {
	return poolallocator.NewIPPoolAllocator(poolName, c.crdClient, c.ipPoolLister)
}
