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

	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/informers/externalversions"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/poolallocator"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "AntreaIPAMController"
)

// Antrea IPAM Controller maintains map of Namespace annotations using
// Namespace informer. In future, which Antrea IPAM support expands,
// this controller can be used to store annotations for other objects,
// such as Statefulsets.
type AntreaIPAMController struct {
	kubeClient        clientset.Interface
	crdClient         clientsetversioned.Interface
	ipPoolInformer    crdinformers.IPPoolInformer
	ipPoolLister      crdlisters.IPPoolLister
	namespaceInformer coreinformers.NamespaceInformer
	namespaceLister   corelisters.NamespaceLister
	podInformer       coreinformers.PodInformer
	podLister         corelisters.PodLister
}

func NewAntreaIPAMController(kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	informerFactory, localNodeInformerFactory informers.SharedInformerFactory,
	crdInformerFactory externalversions.SharedInformerFactory) *AntreaIPAMController {

	namespaceInformer := informerFactory.Core().V1().Namespaces()
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	podInformer := localNodeInformerFactory.Core().V1().Pods()
	c := AntreaIPAMController{
		kubeClient:        kubeClient,
		crdClient:         crdClient,
		ipPoolInformer:    ipPoolInformer,
		ipPoolLister:      ipPoolInformer.Lister(),
		namespaceInformer: namespaceInformer,
		namespaceLister:   namespaceInformer.Lister(),
		podInformer:       podInformer,
		podLister:         podInformer.Lister(),
	}

	return &c
}

func InitializeAntreaIPAMController(kubeClient clientset.Interface, crdClient clientsetversioned.Interface, informerFactory, localNodeInformerFactory informers.SharedInformerFactory, crdInformerFactory externalversions.SharedInformerFactory) (*AntreaIPAMController, error) {
	antreaIPAMController := NewAntreaIPAMController(kubeClient, crdClient, informerFactory, localNodeInformerFactory, crdInformerFactory)

	// Order of init causes antreaIPAMDriver to be initialized first
	// After controller is initialized by agent init, we need to make it
	// know to the driver
	if antreaIPAMDriver == nil {
		return nil, fmt.Errorf("Antrea IPAM driver failed to initialize")
	}

	antreaIPAMDriver.setController(antreaIPAMController)

	return antreaIPAMController, nil
}

// Run starts to watch and process Namespace updates for the Node where Antrea Agent
// is running, and maintain a mapping between Namespace name and IPAM annotations.
func (c *AntreaIPAMController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.V(2).InfoS("Shutting down", "controller", controllerName)
	}()

	klog.InfoS("Starting", "controller", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.namespaceInformer.Informer().HasSynced, c.ipPoolInformer.Informer().HasSynced, c.podInformer.Informer().HasSynced) {
		return
	}

	<-stopCh
}

func (c *AntreaIPAMController) getIPPoolsByPod(namespace, name string) ([]string, []net.IP, *crdv1a2.IPAddressOwner, error) {
	// Find IPPool by Pod
	var IPs []net.IP
	var preallocatedOwner *crdv1a2.IPAddressOwner
	pod, err := c.podLister.Pods(namespace).Get(name)
	if err != nil {
		klog.Warningf("Get pod %s/%s failed, err=%+v", namespace, name, err)
		return nil, nil, nil, err
	}
	// Collect specified IPs if exist
	IPStrings, _ := pod.Annotations[AntreaIPAMPodIPAnnotationKey]
	IPStrings = strings.ReplaceAll(IPStrings, " ", "")
	var ipErr error
	if IPStrings != "" {
		splittedIPStrings := strings.Split(IPStrings, AntreaIPAMAnnotationDelimiter)
		for _, IPString := range splittedIPStrings {
			IP := net.ParseIP(IPString)
			if IPString != "" && IP == nil {
				ipErr = fmt.Errorf("invalid IP annotation %s", IPStrings)
				IPs = nil
				break
			}
			IPs = append(IPs, IP)
		}
	}

	if persistIPString := pod.Annotations[AntreaIPAMPersistIPAnnotationKey]; persistIPString == AntreaIPAMPersistIPAnnotationValue {
	ownerReferenceLoop:
		for _, ownerReference := range pod.OwnerReferences {
			if ownerReference.Controller != nil && *ownerReference.Controller == true {
				switch ownerReference.Kind {
				case "StatefulSet":
					statefulSetName, index, err := k8s.ParseStatefulSetName(name)
					if err != nil {
						klog.Warningf("Invalid StatefulSet name: %s", name)
						break ownerReferenceLoop
					}
					preallocatedOwner = &crdv1a2.IPAddressOwner{StatefulSet: &crdv1a2.StatefulSetOwner{
						Name:      statefulSetName,
						Namespace: namespace,
						Index:     index,
					}}
					break ownerReferenceLoop
				}
			}
		}
	}

	annotations, exists := pod.Annotations[AntreaIPAMAnnotationKey]
	if exists {
		return strings.Split(annotations, AntreaIPAMAnnotationDelimiter), IPs, preallocatedOwner, ipErr
	}

	// Find IPPool by Namespace
	ns, err := c.namespaceLister.Get(namespace)
	if err != nil {
		return nil, nil, nil, nil
	}
	annotations, exists = ns.Annotations[AntreaIPAMAnnotationKey]
	if !exists {
		return nil, nil, nil, nil
	}
	return strings.Split(annotations, AntreaIPAMAnnotationDelimiter), IPs, preallocatedOwner, ipErr
}

func (c *AntreaIPAMController) getPoolAllocatorByPod(namespace, podName string) (*poolallocator.IPPoolAllocator, []net.IP, *crdv1a2.IPAddressOwner, error) {
	poolNames, ips, preAllocatedOwner, err := c.getIPPoolsByPod(namespace, podName)
	if err != nil || len(poolNames) < 1 {
		return nil, nil, nil, err
	}
	// Only one pool is supported as of today
	// TODO - support a pool for each IP version
	ipPool := poolNames[0]
	allocator, err := poolallocator.NewIPPoolAllocator(ipPool, c.crdClient, c.ipPoolLister)
	return allocator, ips, preAllocatedOwner, err
}
