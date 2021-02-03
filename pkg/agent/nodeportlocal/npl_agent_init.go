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
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules"
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/util"

	corev1 "k8s.io/api/core/v1"
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

func cleanupNPLAnnotationForPod(kubeClient clientset.Interface, pod *corev1.Pod) error {
	_, ok := pod.Annotations[nplk8s.NPLAnnotationKey]
	if !ok {
		return nil
	}
	delete(pod.Annotations, nplk8s.NPLAnnotationKey)
	if _, err := kubeClient.CoreV1().Pods(pod.Namespace).Update(context.TODO(), pod, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("unable to update Annotation for Pod %s/%s, %s", pod.Namespace,
			pod.Name, err.Error())
	}
	return nil
}

func addRulesForNPLPorts(portTable *portcache.PortTable, allNPLPorts []rules.PodNodePort) error {
	for _, nplPort := range allNPLPorts {
		portTable.AddUpdateEntry(nplPort.NodePort, nplPort.PodPort, nplPort.PodIP)
	}

	if err := portTable.PodPortRules.AddAllRules(allNPLPorts); err != nil {
		return nil
	}
	return nil
}

// getPodsAndGenRules fetches all the Pods on this Node and looks for valid NPL Annotations, if they
// exist with a valid Node Port, it adds the Node port to the port table and rules. If the Node port
// is invalid or the NPL Annotation is invalid, the NPL Annotation is removed. The Pod event handlers
// take care of allocating a new Node port if required.
func getPodsAndGenRules(kubeClient clientset.Interface, portTable *portcache.PortTable,
	nodeName string) error {
	podList, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return fmt.Errorf("error in fetching the Pods for Node %s: %s", nodeName, err.Error())
	}

	allNPLPorts := []rules.PodNodePort{}
	for _, pod := range podList.Items {
		// For each Pod:
		// check if a valid NPL Annotation exists for this Pod:
		//   if yes, verifiy validity of the Node port, update the port table and add a rule to the
		//   rules buffer.
		annotations := pod.GetAnnotations()
		nplAnnotation, ok := annotations[nplk8s.NPLAnnotationKey]
		if !ok {
			continue
		}
		nplData := []nplk8s.NPLAnnotation{}
		podCopy := pod.DeepCopy()
		err := json.Unmarshal([]byte(nplAnnotation), &nplData)
		if err != nil {
			// if there's an error in this NPL Annotation, clean it up
			err := cleanupNPLAnnotationForPod(kubeClient, podCopy)
			if err != nil {
				return err
			}
			continue
		}

		for _, npl := range nplData {
			if npl.NodePort > portTable.EndPort || npl.NodePort < portTable.StartPort {
				// invalid port, cleanup the NPL Annotation
				if err := cleanupNPLAnnotationForPod(kubeClient, podCopy); err != nil {
					return err
				}
			} else {
				allNPLPorts = append(allNPLPorts, rules.PodNodePort{
					NodePort: npl.NodePort,
					PodPort:  npl.PodPort,
					PodIP:    pod.Status.PodIP,
				})
			}
		}
	}

	if len(allNPLPorts) > 0 {
		if err := addRulesForNPLPorts(portTable, allNPLPorts); err != nil {
			return err
		}
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
		return nil, fmt.Errorf("error while fetching port range: %v", err)
	}
	var ok bool
	portTable, ok := portcache.NewPortTable(start, end)
	if !ok {
		return nil, errors.New("error in initializing NPL port table")
	}

	err = portTable.PodPortRules.Init()
	if err != nil {
		return nil, err
	}

	klog.Info("Will fetch Pods and generate NPL rules for these Pods")
	if err := getPodsAndGenRules(kubeClient, portTable, nodeName); err != nil {
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
