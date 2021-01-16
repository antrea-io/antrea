// +build !windows

// Copyright 2020 Antrea Authors
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

package nodeportlocal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	nplk8s "github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// Set resyncPeriod to 0 to disable resyncing.
// UpdateFunc event handler will be called only when the object is actually updated.
const resyncPeriod = 0 * time.Minute

func updatePodNodePortCache(cache map[string][]nplk8s.PodNodePort, podIP string, nodePort, podPort int) {
	v := nplk8s.PodNodePort{
		NodePort: nodePort,
		PodPort:  podPort,
	}
	_, exists := cache[podIP]
	if !exists {
		cache[podIP] = []nplk8s.PodNodePort{v}
		return
	}
	cache[podIP] = append(cache[podIP], v)
}

// rulesToPodPortMap is responsible for going through the NPL rules and figures out if some of these
// rules are still needed. To check if a rule is needed, it first checks if the relevant Pod exists,
// if not, it deletes the rule. This function adds the port rules to the portTable and responds with
// a list of visited Pods.
func rulesToPodPortMap(portTable *portcache.PortTable, kubeClient clientset.Interface) (map[string][]nplk8s.PodNodePort, error) {
	podPortRules, err := portTable.PodPortRules.GetAllRules()
	if err != nil {
		klog.Errorf("error in fetching the Pod port rules: %s", err.Error())
		return nil, errors.New("error in fetching the Pod port rules: " + err.Error())
	}

	podNodePortCache := make(map[string][]nplk8s.PodNodePort)

	for k, v := range podPortRules {
		// k: NodePort
		// v: {PodIP,Pod port}
		if k > portTable.EndPort || k < portTable.StartPort {
			// delete this rule, as the Node port falls in an invalid range
			err := portTable.PodPortRules.DeleteRule(k, v.PodIP)
			if err != nil {
				klog.Errorf("error in deleting the rule for port %d and Pod IP %s", k, v.PodIP)
				continue
			}
		}
		podList, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{
			FieldSelector: "status.podIP=" + v.PodIP,
		})
		if err != nil {
			klog.Infof("error in fetching Pod with IP address %s: %s", v.PodIP, err.Error())
			continue
		}
		if len(podList.Items) == 0 {
			klog.Infof("couldn't find a Pod for IP address %s, will delete it's entry", v.PodIP)
			// delete this port's entry from the rules
			err := portTable.PodPortRules.DeleteRule(k, v.PodIP)
			if err != nil {
				// TODO: need to handle this case properly, currently, it would mean that Antrea thinks
				// this port is free to allocate, however the rule for this port forwards the packets
				// to a non-existent Pod
				klog.Errorf("error in deleting the rule for port %d and Pod IP %s: %s", k, v.PodIP, err.Error())
			}
			continue
		}
		// Pod exists, add it to podPortTable
		// error is already checked
		klog.V(2).Infof("adding an entry for Node port %d, Pod %s and Pod port: %d", k, v.PodIP, v.PodPort)
		portTable.AddUpdateEntry(k, v.PodPort, v.PodIP)

		updatePodNodePortCache(podNodePortCache, v.PodIP, k, v.PodPort)
	}

	return podNodePortCache, err
}

// podsToPortMap goes through all the Pods for this node and figures out if there's a need for NPL
// for each node. If yes, it assigns a port for this Pod and adds that as a rule.
func podsToPodPortMap(podCache map[string][]nplk8s.PodNodePort, kubeClient clientset.Interface, portTable *portcache.PortTable,
	nodeName string) error {
	podList, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		klog.Errorf("error in fetching the Pods for Node %s: %s", nodeName, err.Error())
		return errors.New("error in fetching Pods for the Node" + nodeName)
	}
	for _, pod := range podList.Items {
		// for each Pod:
		// check if its already part of the podCache, which indicates that the Pod is already
		// part of a rule
		// if this Pod doesn't have any rule, compute a rule from the Pod ports, allocate a port
		// and add it to port table
		podIP := pod.Status.PodIP
		if podIP == "" {
			klog.Infof("IP address not found for Pod %s/%s", pod.Namespace, pod.Name)
			continue
		}

		newPod := pod.DeepCopy()
		// clear out the annotations
		newPod.SetAnnotations(make(map[string]string))
		nplAnnotations := []nplk8s.NPLAnnotation{}
		updatePodAnnotation := false
		podExists := false
		var nodePort int

		if _, ok := podCache[podIP]; ok {
			podExists = true
			// the rule for this Pod already exists, ensure annotations are right
			for _, v := range podCache[podIP] {
				nplAnnotations = append(nplAnnotations, nplk8s.NPLAnnotation{
					PodPort:  v.PodPort,
					NodeIP:   pod.Status.HostIP,
					NodePort: v.NodePort,
				})
			}
		}

		if !podExists {
			for _, c := range pod.Spec.Containers {
				for _, cport := range c.Ports {
					port := int(cport.ContainerPort)
					if !portTable.RuleExists(podIP, port) {
						nodePort, err = portTable.AddRule(podIP, port)
						if err != nil {
							klog.Errorf("failed to add rule for Pod %s/%s: %s", pod.Namespace, pod.Name, err.Error())
							continue
						}
					}
					nplAnnotations = append(nplAnnotations, nplk8s.NPLAnnotation{
						PodPort:  port,
						NodeIP:   pod.Status.HostIP,
						NodePort: nodePort,
					})
				}
			}
		}

		if len(nplAnnotations) > 0 {
			jsonMarshalled, _ := json.Marshal(nplAnnotations)
			oldNPLAnnotations, err := nplk8s.ParsePodNPLAnnotations(pod)
			if err != nil {
				klog.Warningf("couldn't fetch the NPL annotations %s, will update the annotations", err.Error())
				newPod.SetAnnotations(map[string]string{
					nplk8s.NPLAnnotationKey: string(jsonMarshalled),
				})
				updatePodAnnotation = true
			}
			// check if the annotations differ
			if nplk8s.IsAnnotationDifferent(oldNPLAnnotations, nplAnnotations) {
				newPod.SetAnnotations(map[string]string{
					nplk8s.NPLAnnotationKey: string(jsonMarshalled),
				})
				updatePodAnnotation = true
			}
		}

		if updatePodAnnotation {
			if _, err := kubeClient.CoreV1().Pods(pod.Namespace).Update(context.TODO(), newPod, metav1.UpdateOptions{}); err != nil {
				klog.Warningf("unable to update annotation for Pod %s/%s, error: %s", newPod.Namespace, newPod.Name, err.Error())
				return err
			}
		}
		klog.V(2).Infof("successfully updated annotation for Pod %s/%s", pod.Namespace, pod.Name)
	}
	return nil
}

func genPodPortMap(portTable *portcache.PortTable, kubeClient clientset.Interface, nodeName string) error {
	podNodePortCache, err := rulesToPodPortMap(portTable, kubeClient)
	if err != nil {
		return err
	}

	err = podsToPodPortMap(podNodePortCache, kubeClient, portTable, nodeName)
	if err != nil {
		return err
	}
	return nil
}

// InitializeNPLAgent initializes the NodePortLocal (NPL) agent.
// It initializes the port table cache to keep track of Node ports available for use by NPL,
// sets up event handlers to handle Pod add, update and delete events.
// When a Pod gets created, a free Node port is obtained from the port table cache and a DNAT rule is added to NAT traffic to the Pod's ip:port.
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portRange, nodeName string) (*nplk8s.NPLController, error) {
	start, end, err := util.ParsePortsRange(portRange)
	if err != nil {
		return nil, fmt.Errorf("something went wrong while fetching port range: %v", err)
	}
	var ok bool
	portTable, ok := portcache.NewPortTable(start, end)
	if !ok {
		return nil, errors.New("NPL port table could not be initialized")
	}

	err = portTable.PodPortRules.Init()
	if err != nil {
		return nil, err
	}

	err = genPodPortMap(portTable, kubeClient, nodeName)
	if err != nil {
		return nil, err
	}

	return InitController(kubeClient, informerFactory, portTable, nodeName)
}

// InitController initializes the NPLController with appropriate Pod and Service Informers.
// This function can be used independently while unit testing without using InitializeNPLAgent function.
func InitController(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portTable *portcache.PortTable, nodeName string) (*nplk8s.NPLController, error) {
	// Watch only the Pods which belong to the Node where the agent is running.
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	}
	podInformer := coreinformers.NewFilteredPodInformer(
		kubeClient,
		metav1.NamespaceAll,
		resyncPeriod,
		cache.Indexers{},
		listOptions,
	)

	svcInformer := informerFactory.Core().V1().Services().Informer()

	c := nplk8s.NewNPLController(kubeClient,
		podInformer,
		svcInformer,
		resyncPeriod,
		portTable)
	c.RemoveNPLAnnotationFromPods()

	return c, nil
}
