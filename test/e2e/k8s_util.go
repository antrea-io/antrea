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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
)

type KubernetesUtils struct {
	*TestData
	podCache map[string][]v1.Pod
	podLock  sync.Mutex
}

func NewKubernetesUtils(data *TestData) (*KubernetesUtils, error) {
	return &KubernetesUtils{
		TestData: data,
		podCache: map[string][]v1.Pod{},
	}, nil
}

// GetPodByLabel returns a Pod with the matching Namespace and "pod" label.
func (k *KubernetesUtils) GetPodByLabel(ns string, name string) (*v1.Pod, error) {
	pods, err := k.getPodsUncached(ns, "pod", name)
	if err != nil || len(pods) == 0 {
		return nil, errors.WithMessagef(err, "unable to get Pod in Namespace %s with label pod=%s", ns, name)
	}
	return &pods[0], nil
}

func (k *KubernetesUtils) getPodsUncached(ns string, key, val string) ([]v1.Pod, error) {
	v1PodList, err := k.clientset.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%v=%v", key, val),
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to list pods")
	}
	return v1PodList.Items, nil
}

// GetPodsByLabel returns an array of all Pods in the given Namespace having a k/v label pair.
func (k *KubernetesUtils) GetPodsByLabel(ns string, key string, val string) ([]v1.Pod, error) {
	k.podLock.Lock()
	defer k.podLock.Unlock()
	if p, ok := k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)]; ok {
		return p, nil
	}

	v1PodList, err := k.getPodsUncached(ns, key, val)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to list pods")
	}
	k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)] = v1PodList
	return v1PodList, nil
}

func (k *KubernetesUtils) probe(
	pod *v1.Pod,
	podName string,
	containerName string,
	dstAddr string,
	dstName string,
	port int32,
	protocol v1.Protocol,
) PodConnectivityMark {
	protocolStr := map[v1.Protocol]string{
		v1.ProtocolTCP:  "tcp",
		v1.ProtocolUDP:  "udp",
		v1.ProtocolSCTP: "sctp",
	}
	// There seems to be an issue when running Antrea in Kind where tunnel traffic is dropped at
	// first. This leads to the first test being run consistently failing. To avoid this issue
	// until it is resolved, we try to connect 3 times.
	// See https://github.com/antrea-io/antrea/issues/467.
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf("for i in $(seq 1 3); do /agnhost connect %s:%d --timeout=1s --protocol=%s; done;", dstAddr, port, protocolStr[protocol]),
	}
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", pod.Name, containerName, pod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.runCommandFromPod(pod.Namespace, pod.Name, containerName, cmd)
	// It needs to check both err and stderr because:
	// 1. The probe tried 3 times. If it checks err only, failure+failure+success would be considered connected.
	// 2. There might be an issue in Pod exec API that it sometimes doesn't return error when the probe fails. See #2394.
	if err != nil || stderr != "" {
		// log this error as trace since may be an expected failure
		log.Tracef("%s -> %s: error when running command: err - %v /// stdout - %s /// stderr - %s", podName, dstName, err, stdout, stderr)
		// If err != nil and stderr == "", then it means this probe failed because of
		// the command instead of connectivity. For example, container name doesn't exist.
		if stderr == "" {
			return Error
		}
		return decideProbeResult(stderr, 3)
	}
	return Connected
}

// decideProbeResult uses the probe stderr to decide the connectivity.
func decideProbeResult(stderr string, probeNum int) PodConnectivityMark {
	countConnected := probeNum - strings.Count(stderr, "\n")
	countDropped := strings.Count(stderr, "TIMEOUT")
	// For our UDP rejection cases, agnhost will return:
	//   For IPv4: 'UNKNOWN: read udp [src]->[dst]: read: no route to host'
	//   For IPv6: 'UNKNOWN: read udp [src]->[dst]: read: permission denied'
	// To avoid incorrect identification, we use 'no route to host' and
	// `permission denied`, instead of 'UNKNOWN' as key string.
	// For our other protocols rejection cases, agnhost will return 'REFUSED'.
	countRejected := strings.Count(stderr, "REFUSED") + strings.Count(stderr, "no route to host") + strings.Count(stderr, "permission denied")

	if countRejected == 0 && countConnected > 0 {
		return Connected
	}
	if countConnected == 0 && countRejected > 0 {
		return Rejected
	}
	if countDropped == probeNum {
		return Dropped
	}
	return Error
}

// Probe execs into a Pod and checks its connectivity to another Pod. Of course it
// assumes that the target Pod is serving on the input port, and also that agnhost
// is installed. The connectivity from source Pod to all IPs of the target Pod
// should be consistent. Otherwise, Error PodConnectivityMark will be returned.
func (k *KubernetesUtils) Probe(ns1, pod1, ns2, pod2 string, port int32, protocol v1.Protocol) (PodConnectivityMark, error) {
	fromPods, err := k.GetPodsByLabel(ns1, "pod", pod1)
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s: %v", ns1, err)
	}
	if len(fromPods) == 0 {
		return Error, fmt.Errorf("no Pod of label pod=%s in Namespace %s found", pod1, ns1)
	}
	fromPod := fromPods[0]

	toPods, err := k.GetPodsByLabel(ns2, "pod", pod2)
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s: %v", ns2, err)
	}
	if len(toPods) == 0 {
		return Error, fmt.Errorf("no Pod of label pod=%s in Namespace %s found", pod2, ns2)
	}
	toPod := toPods[0]

	// Both IPv4 and IPv6 address should be tested.
	connectivity := Unknown
	for _, eachIP := range toPod.Status.PodIPs {
		toIP := eachIP.IP
		// If it's an IPv6 address, add "[]" around it.
		if strings.Contains(toIP, ":") {
			toIP = fmt.Sprintf("[%s]", toIP)
		}
		// HACK: inferring container name as c80, c81, etc, for simplicity.
		containerName := fmt.Sprintf("c%v", port)
		curConnectivity := k.probe(&fromPod, fmt.Sprintf("%s/%s", ns1, pod1), containerName, toIP, fmt.Sprintf("%s/%s", ns2, pod2), port, protocol)
		if connectivity == Unknown {
			connectivity = curConnectivity
		} else if connectivity != curConnectivity {
			return Error, nil
		}
	}
	return connectivity, nil
}

// ProbeAddr execs into a Pod and checks its connectivity to an arbitrary destination
// address.
func (k *KubernetesUtils) ProbeAddr(ns, podLabelKey, podLabelValue, dstAddr string, port int32, protocol v1.Protocol) (PodConnectivityMark, error) {
	fromPods, err := k.GetPodsByLabel(ns, podLabelKey, podLabelValue)
	if err != nil {
		return Error, fmt.Errorf("unable to get Pods from Namespace %s: %v", ns, err)
	}
	if len(fromPods) == 0 {
		return Error, fmt.Errorf("no Pod of label podLabelKey=%s podLabelValue=%s in Namespace %s found", podLabelKey, podLabelValue, ns)
	}
	fromPod := fromPods[0]
	containerName := fromPod.Spec.Containers[0].Name
	// If it's an IPv6 address, add "[]" around it.
	if strings.Contains(dstAddr, ":") {
		dstAddr = fmt.Sprintf("[%s]", dstAddr)
	}
	connectivity := k.probe(&fromPod, fmt.Sprintf("%s/%s", ns, podLabelValue), containerName, dstAddr, dstAddr, port, protocol)
	return connectivity, nil
}

// CreateOrUpdateNamespace is a convenience function for idempotent setup of Namespaces
func (k *KubernetesUtils) CreateOrUpdateNamespace(n string, labels map[string]string) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n,
			Labels: labels,
		},
	}
	log.Infof("Creating Namespace %s...", n)
	nsr, err := k.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Created Namespace %s", n)
		return nsr, nil
	}

	log.Infof("Unable to create Namespace %s, let's try updating it instead (error: %s)", ns.Name, err)
	nsr, err = k.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		log.Infof("Unable to update Namespace %s: %s", ns, err)
	}

	nsr, err = k.clientset.CoreV1().Namespaces().Get(context.TODO(), ns.Name, metav1.GetOptions{})
	if err != nil {
		log.Infof("Unable to get Namespace %s: %s", ns, err)
	}
	if nsr != nil {
		log.Infof("Namespace %s status: %s", ns.Name, nsr)
	}
	return nsr, err
}

// CreateOrUpdateDeployment is a convenience function for idempotent setup of deployments
func (k *KubernetesUtils) CreateOrUpdateDeployment(ns, deploymentName string, replicas int32, labels map[string]string) (*appsv1.Deployment, error) {
	zero := int64(0)
	log.Infof("Creating/updating Deployment '%s/%s'", ns, deploymentName)
	makeContainerSpec := func(port int32, protocol v1.Protocol) v1.Container {
		var args []string
		switch protocol {
		case v1.ProtocolTCP:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --tcp --http=false --port=%d", port)}
		case v1.ProtocolUDP:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port=%d", port)}
		case v1.ProtocolSCTP:
			args = []string{"/agnhost porter"}
		default:
			args = []string{fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port=%d & /agnhost serve-hostname --tcp --http=false --port=%d & /agnhost porter", port, port)}

		}
		return v1.Container{
			Name:            fmt.Sprintf("c%d", port),
			ImagePullPolicy: v1.PullIfNotPresent,
			Image:           agnhostImage,
			Env:             []v1.EnvVar{{Name: fmt.Sprintf("SERVE_SCTP_PORT_%d", port), Value: "foo"}},
			Command:         []string{"/bin/bash", "-c"},
			Args:            args,
			SecurityContext: &v1.SecurityContext{},
			Ports: []v1.ContainerPort{
				{
					ContainerPort: port,
					Name:          fmt.Sprintf("serve-%d", port),
				},
			},
		}
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Labels:    labels,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:    labels,
					Namespace: ns,
				},
				Spec: v1.PodSpec{
					TerminationGracePeriodSeconds: &zero,
					Containers: []v1.Container{
						makeContainerSpec(80, "ALL"),
						makeContainerSpec(81, "ALL"),
						makeContainerSpec(8080, v1.ProtocolTCP),
						makeContainerSpec(8081, v1.ProtocolTCP),
						makeContainerSpec(8082, v1.ProtocolTCP),
						makeContainerSpec(8083, v1.ProtocolTCP),
						makeContainerSpec(8084, v1.ProtocolTCP),
						makeContainerSpec(8085, v1.ProtocolTCP),
					},
				},
			},
		},
	}

	d, err := k.clientset.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Created deployment '%s/%s'", ns, d.Name)
		return d, nil
	}

	log.Debugf("Unable to create deployment %s in Namespace %s, let's try update instead", deployment.Name, ns)
	d, err = k.clientset.AppsV1().Deployments(ns).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("Unable to update deployment '%s/%s': %s", ns, deployment.Name, err)
	}
	return d, err
}

// BuildService is a convenience function for building a corev1.Service spec.
func (k *KubernetesUtils) BuildService(svcName, svcNS string, port, targetPort int, selector map[string]string, serviceType *v1.ServiceType) *v1.Service {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: svcNS,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Port:       int32(port),
				TargetPort: intstr.FromInt(targetPort),
			}},
			Selector: selector,
		},
	}
	if serviceType != nil {
		service.Spec.Type = *serviceType
	}
	return service
}

// CreateOrUpdateService is a convenience function for updating/creating Services.
func (k *KubernetesUtils) CreateOrUpdateService(svc *v1.Service) (*v1.Service, error) {
	log.Infof("Creating/updating Service %s in ns %s", svc.Name, svc.Namespace)
	svcReturned, err := k.clientset.CoreV1().Services(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})

	if err != nil {
		service, err := k.clientset.CoreV1().Services(svc.Namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create Service %s/%s: %s", svc.Namespace, svc.Name, err)
			return nil, err
		}
		return service, nil
	} else if svcReturned.Name != "" {
		log.Debugf("Service %s/%s already exists, updating", svc.Namespace, svc.Name)
		clusterIP := svcReturned.Spec.ClusterIP
		svcReturned.Spec = svc.Spec
		svcReturned.Spec.ClusterIP = clusterIP
		service, err := k.clientset.CoreV1().Services(svc.Namespace).Update(context.TODO(), svcReturned, metav1.UpdateOptions{})
		return service, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Service %s", svc.Name)
}

// GetService is a convenience function for getting Service
func (k *KubernetesUtils) GetService(namespace, name string) (*v1.Service, error) {
	res, err := k.clientset.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteService is a convenience function for deleting a Service by Namespace and name.
func (k *KubernetesUtils) DeleteService(ns, name string) error {
	log.Infof("Deleting Service %s in ns %s", name, ns)
	err := k.clientset.CoreV1().Services(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete Service %s", name)
	}
	return nil
}

// CleanServices is a convenience function for deleting Services in the cluster.
func (k *KubernetesUtils) CleanServices(namespaces []string) error {
	for _, ns := range namespaces {
		l, err := k.clientset.CoreV1().Services(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list Services in ns %s", ns)
		}
		for _, svc := range l.Items {
			if err := k.DeleteService(svc.Namespace, svc.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildServiceAccount is a convenience function for building a corev1.SerivceAccount spec.
func (k *KubernetesUtils) BuildServiceAccount(name, ns string, labels map[string]string) *v1.ServiceAccount {
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
	}
	return serviceAccount
}

// CreateOrUpdateServiceAccount is a convenience function for updating/creating ServiceAccount.
func (k *KubernetesUtils) CreateOrUpdateServiceAccount(sa *v1.ServiceAccount) (*v1.ServiceAccount, error) {

	log.Infof("Creating/updating ServiceAccount %s in ns %s", sa.Name, sa.Namespace)
	saReturned, err := k.clientset.CoreV1().ServiceAccounts(sa.Namespace).Get(context.TODO(), sa.Name, metav1.GetOptions{})

	if err != nil {
		serviceAccount, err := k.clientset.CoreV1().ServiceAccounts(sa.Namespace).Create(context.TODO(), sa, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create ServiceAccount %s/%s: %s", sa.Namespace, sa.Name, err)
			return nil, err
		}
		return serviceAccount, nil
	}
	log.Debugf("ServiceAccount %s/%s already exists, updating", sa.Namespace, sa.Name)
	saReturned.Labels = sa.Labels
	serviceAccount, err := k.clientset.CoreV1().ServiceAccounts(sa.Namespace).Update(context.TODO(), saReturned, metav1.UpdateOptions{})
	if err != nil {
		log.Infof("Unable to update ServiceAccount %s/%s: %s", sa.Namespace, sa.Name, err)
		return nil, err
	}
	return serviceAccount, nil
}

// DeleteServiceAccount is a convenience function for deleting a ServiceAccount by Namespace and name.
func (k *KubernetesUtils) DeleteServiceAccount(ns, name string) error {
	log.Infof("Deleting ServiceAccount %s in ns %s", name, ns)
	err := k.clientset.CoreV1().ServiceAccounts(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete ServiceAccount %s in ns %s", name, ns)
	}
	return nil
}

// CreateOrUpdateNetworkPolicy is a convenience function for updating/creating netpols. Updating is important since
// some tests update a network policy to confirm that mutation works with a CNI.
func (k *KubernetesUtils) CreateOrUpdateNetworkPolicy(netpol *v1net.NetworkPolicy) (*v1net.NetworkPolicy, error) {
	log.Infof("Creating/updating NetworkPolicy '%s/%s'", netpol.Namespace, netpol.Name)
	np, err := k.clientset.NetworkingV1().NetworkPolicies(netpol.Namespace).Update(context.TODO(), netpol, metav1.UpdateOptions{})
	if err == nil {
		return np, err
	}

	log.Debugf("Unable to update NetworkPolicy '%s/%s', let's try creating it instead (error: %s)", netpol.Namespace, netpol.Name, err)
	np, err = k.clientset.NetworkingV1().NetworkPolicies(netpol.Namespace).Create(context.TODO(), netpol, metav1.CreateOptions{})
	if err != nil {
		log.Debugf("Unable to create network policy: %s", err)
	}
	return np, err
}

// GetNetworkPolicy is a convenience function for getting k8s NetworkPolicies.
func (k *KubernetesUtils) GetNetworkPolicy(namespace, name string) (*v1net.NetworkPolicy, error) {
	res, err := k.clientset.NetworkingV1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteNetworkPolicy is a convenience function for deleting NetworkPolicy by name and Namespace.
func (k *KubernetesUtils) DeleteNetworkPolicy(ns, name string) error {
	log.Infof("Deleting NetworkPolicy '%s/%s'", ns, name)
	err := k.clientset.NetworkingV1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete NetworkPolicy '%s'", name)
	}
	return nil
}

// CleanNetworkPolicies is a convenience function for deleting NetworkPolicies in the provided namespaces.
func (k *KubernetesUtils) CleanNetworkPolicies(namespaces []string) error {
	for _, ns := range namespaces {
		l, err := k.clientset.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list NetworkPolicy in Namespace '%s'", ns)
		}
		for _, np := range l.Items {
			if err = k.DeleteNetworkPolicy(np.Namespace, np.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateTier is a convenience function for creating an Antrea Policy Tier by name and priority.
func (k *KubernetesUtils) CreateNewTier(name string, tierPriority int32) (*crdv1alpha1.Tier, error) {
	log.Infof("Creating tier %s", name)
	_, err := k.crdClient.CrdV1alpha1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		tr := &crdv1alpha1.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       crdv1alpha1.TierSpec{Priority: tierPriority},
		}
		tr, err = k.crdClient.CrdV1alpha1().Tiers().Create(context.TODO(), tr, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create tier %s: %s", name, err)
		}
		return tr, err
	}
	return nil, fmt.Errorf("tier with name %s already exists", name)
}

// GetTier is a convenience function for getting Tier.
func (k *KubernetesUtils) GetTier(name string) (*crdv1alpha1.Tier, error) {
	res, err := k.crdClient.CrdV1alpha1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// UpdateTier is a convenience function for updating an Antrea Policy Tier.
func (k *KubernetesUtils) UpdateTier(tier *crdv1alpha1.Tier) (*crdv1alpha1.Tier, error) {
	log.Infof("Updating tier %s", tier.Name)
	updatedTier, err := k.crdClient.CrdV1alpha1().Tiers().Update(context.TODO(), tier, metav1.UpdateOptions{})
	return updatedTier, err
}

// DeleteTier is a convenience function for deleting an Antrea Policy Tier with specific name.
func (k *KubernetesUtils) DeleteTier(name string) error {
	_, err := k.crdClient.CrdV1alpha1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to get tier %s", name)
	}
	log.Infof("Deleting tier %s", name)
	if err = k.crdClient.CrdV1alpha1().Tiers().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		return errors.Wrapf(err, "unable to delete tier %s", name)
	}
	return nil
}

// CreateOrUpdateV1Alpha2CG is a convenience function for idempotent setup of crd/v1alpha2 ClusterGroups
func (k *KubernetesUtils) CreateOrUpdateV1Alpha2CG(cg *crdv1alpha2.ClusterGroup) (*crdv1alpha2.ClusterGroup, error) {
	log.Infof("Creating/updating ClusterGroup %s", cg.Name)
	cgReturned, err := k.crdClient.CrdV1alpha2().ClusterGroups().Get(context.TODO(), cg.Name, metav1.GetOptions{})
	if err != nil {
		cgr, err := k.crdClient.CrdV1alpha2().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create cluster group %s: %v", cg.Name, err)
			return nil, err
		}
		return cgr, nil
	} else if cgReturned.Name != "" {
		log.Debugf("ClusterGroup with name %s already exists, updating", cg.Name)
		cgReturned.Spec = cg.Spec
		cgr, err := k.crdClient.CrdV1alpha2().ClusterGroups().Update(context.TODO(), cgReturned, metav1.UpdateOptions{})
		return cgr, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterGroup %s", cg.Name)
}

// CreateOrUpdateV1Alpha3CG is a convenience function for idempotent setup of crd/v1alpha3 ClusterGroups
func (k *KubernetesUtils) CreateOrUpdateV1Alpha3CG(cg *crdv1alpha3.ClusterGroup) (*crdv1alpha3.ClusterGroup, error) {
	log.Infof("Creating/updating ClusterGroup %s", cg.Name)
	cgReturned, err := k.crdClient.CrdV1alpha3().ClusterGroups().Get(context.TODO(), cg.Name, metav1.GetOptions{})
	if err != nil {
		cgr, err := k.crdClient.CrdV1alpha3().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create cluster group %s: %v", cg.Name, err)
			return nil, err
		}
		return cgr, nil
	} else if cgReturned.Name != "" {
		log.Debugf("ClusterGroup with name %s already exists, updating", cg.Name)
		cgReturned.Spec = cg.Spec
		cgr, err := k.crdClient.CrdV1alpha3().ClusterGroups().Update(context.TODO(), cgReturned, metav1.UpdateOptions{})
		return cgr, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterGroup %s", cg.Name)
}

func (k *KubernetesUtils) GetV1Alpha2CG(cgName string) (*crdv1alpha2.ClusterGroup, error) {
	return k.crdClient.CrdV1alpha2().ClusterGroups().Get(context.TODO(), cgName, metav1.GetOptions{})
}

func (k *KubernetesUtils) GetV1Alpha3CG(cgName string) (*crdv1alpha3.ClusterGroup, error) {
	return k.crdClient.CrdV1alpha3().ClusterGroups().Get(context.TODO(), cgName, metav1.GetOptions{})
}

// CreateCG is a convenience function for creating an Antrea ClusterGroup by name and selector.
func (k *KubernetesUtils) CreateCG(name string, pSelector, nSelector *metav1.LabelSelector, ipBlocks []crdv1alpha1.IPBlock) (*crdv1alpha3.ClusterGroup, error) {
	log.Infof("Creating clustergroup %s", name)
	_, err := k.crdClient.CrdV1alpha3().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		cg := &crdv1alpha3.ClusterGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
		if pSelector != nil {
			cg.Spec.PodSelector = pSelector
		}
		if nSelector != nil {
			cg.Spec.NamespaceSelector = nSelector
		}
		if len(ipBlocks) > 0 {
			cg.Spec.IPBlocks = ipBlocks
		}
		cg, err = k.crdClient.CrdV1alpha3().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create clustergroup %s: %s", name, err)
		}
		return cg, err
	}
	return nil, fmt.Errorf("clustergroup with name %s already exists", name)
}

// GetCG is a convenience function for getting ClusterGroups
func (k *KubernetesUtils) GetCG(name string) (*crdv1alpha2.ClusterGroup, error) {
	res, err := k.crdClient.CrdV1alpha2().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteV1Alpha2CG is a convenience function for deleting crd/v1alpha2 ClusterGroup by name.
func (k *KubernetesUtils) DeleteV1Alpha2CG(name string) error {
	log.Infof("Deleting ClusterGroup %s", name)
	err := k.crdClient.CrdV1alpha2().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete ClusterGroup %s", name)
	}
	return nil
}

// DeleteV1Alpha3CG is a convenience function for deleting core/v1alpha3 ClusterGroup by name.
func (k *KubernetesUtils) DeleteV1Alpha3CG(name string) error {
	log.Infof("deleting ClusterGroup %s", name)
	err := k.crdClient.CrdV1alpha3().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete ClusterGroup %s", name)
	}
	return nil
}

// CleanCGs is a convenience function for deleting all ClusterGroups in the cluster.
func (k *KubernetesUtils) CleanCGs() error {
	l, err := k.crdClient.CrdV1alpha2().ClusterGroups().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list ClusterGroups in v1alpha2")
	}
	for _, cg := range l.Items {
		if err := k.DeleteV1Alpha2CG(cg.Name); err != nil {
			return err
		}
	}
	l2, err := k.crdClient.CrdV1alpha3().ClusterGroups().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list ClusterGroups in v1alpha3")
	}
	for _, cg := range l2.Items {
		if err := k.DeleteV1Alpha3CG(cg.Name); err != nil {
			return err
		}
	}
	return nil
}

// CreateOrUpdateACNP is a convenience function for updating/creating AntreaClusterNetworkPolicies.
func (k *KubernetesUtils) CreateOrUpdateACNP(cnp *crdv1alpha1.ClusterNetworkPolicy) (*crdv1alpha1.ClusterNetworkPolicy, error) {
	log.Infof("Creating/updating ClusterNetworkPolicy %s", cnp.Name)
	cnpReturned, err := k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), cnp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating ClusterNetworkPolicy %s", cnp.Name)
		cnp, err = k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Create(context.TODO(), cnp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create ClusterNetworkPolicy: %s", err)
		}
		return cnp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("ClusterNetworkPolicy with name %s already exists, updating", cnp.Name)
		cnpReturned.Spec = cnp.Spec
		cnp, err = k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Update(context.TODO(), cnpReturned, metav1.UpdateOptions{})
		return cnp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterNetworkPolicy %s", cnp.Name)
}

// GetACNP is a convenience function for getting AntreaClusterNetworkPolicies.
func (k *KubernetesUtils) GetACNP(name string) (*crdv1alpha1.ClusterNetworkPolicy, error) {
	res, err := k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteACNP is a convenience function for deleting ACNP by name.
func (k *KubernetesUtils) DeleteACNP(name string) error {
	log.Infof("Deleting AntreaClusterNetworkPolicies %s", name)
	err := k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete ClusterNetworkPolicy %s", name)
	}
	return nil
}

// CleanACNPs is a convenience function for deleting all Antrea ClusterNetworkPolicies in the cluster.
func (k *KubernetesUtils) CleanACNPs() error {
	l, err := k.crdClient.CrdV1alpha1().ClusterNetworkPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list AntreaClusterNetworkPolicies")
	}
	for _, cnp := range l.Items {
		if err = k.DeleteACNP(cnp.Name); err != nil {
			return err
		}
	}
	return nil
}

// CreateOrUpdateANP is a convenience function for updating/creating Antrea NetworkPolicies.
func (k *KubernetesUtils) CreateOrUpdateANP(anp *crdv1alpha1.NetworkPolicy) (*crdv1alpha1.NetworkPolicy, error) {
	log.Infof("Creating/updating Antrea NetworkPolicy %s/%s", anp.Namespace, anp.Name)
	cnpReturned, err := k.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating Antrea NetworkPolicy %s", anp.Name)
		anp, err = k.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create Antrea NetworkPolicy: %s", err)
		}
		return anp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("Antrea NetworkPolicy with name %s already exists, updating", anp.Name)
		anp, err = k.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Update(context.TODO(), anp, metav1.UpdateOptions{})
		return anp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Antrea NetworkPolicy %s", anp.Name)
}

// GetANP is a convenience function for getting AntreaNetworkPolicies.
func (k *KubernetesUtils) GetANP(namespace, name string) (*crdv1alpha1.NetworkPolicy, error) {
	res, err := k.crdClient.CrdV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteANP is a convenience function for deleting ANP by name and Namespace.
func (k *KubernetesUtils) DeleteANP(ns, name string) error {
	log.Infof("Deleting Antrea NetworkPolicy '%s/%s'", ns, name)
	err := k.crdClient.CrdV1alpha1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete Antrea NetworkPolicy %s", name)
	}
	return nil
}

// CleanANPs is a convenience function for deleting all Antrea NetworkPolicies in provided namespaces.
func (k *KubernetesUtils) CleanANPs(namespaces []string) error {
	for _, ns := range namespaces {
		l, err := k.crdClient.CrdV1alpha1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list Antrea NetworkPolicies in ns %s", ns)
		}
		for _, anp := range l.Items {
			if err = k.DeleteANP(anp.Namespace, anp.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *KubernetesUtils) waitForPodInNamespace(ns string, pod string) ([]string, error) {
	log.Infof("Waiting for Pod '%s/%s'", ns, pod)
	for {
		k8sPod, err := k.GetPodByLabel(ns, pod)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to get Pod '%s/%s'", ns, pod)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return nil, errors.WithMessagef(err, "unable to get IP of Pod '%s/%s'", ns, pod)
			}
			var podIPs []string
			for _, podIP := range k8sPod.Status.PodIPs {
				podIPs = append(podIPs, podIP.IP)
			}
			log.Debugf("IPs of Pod '%s/%s': %s", ns, pod, podIPs)
			log.Debugf("Pod running: %s/%s", ns, pod)
			return podIPs, nil
		}
		log.Infof("Pod '%s/%s' not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func (k *KubernetesUtils) waitForHTTPServers(allPods []Pod) error {
	const maxTries = 10
	log.Infof("waiting for HTTP servers (ports 80, 81 and 8080:8085) to become ready")

	serversAreReady := func() bool {
		reachability := NewReachability(allPods, Connected)
		k.Validate(allPods, reachability, []int32{80, 81, 8080, 8081, 8082, 8083, 8084, 8085}, v1.ProtocolTCP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}

		k.Validate(allPods, reachability, []int32{80, 81}, v1.ProtocolUDP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}

		k.Validate(allPods, reachability, []int32{80, 81}, v1.ProtocolSCTP)
		if _, wrong, _ := reachability.Summary(); wrong != 0 {
			return false
		}
		return true
	}

	for i := 0; i < maxTries; i++ {
		if serversAreReady() {
			log.Infof("All HTTP servers are ready")
			return nil
		}
		time.Sleep(defaultInterval)
	}
	return errors.Errorf("after %d tries, HTTP servers are not ready", maxTries)
}

func (k *KubernetesUtils) validateOnePort(allPods []Pod, reachability *Reachability, port int32, protocol v1.Protocol) {
	type probeResult struct {
		podFrom      Pod
		podTo        Pod
		connectivity PodConnectivityMark
		err          error
	}
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo Pod, port int32) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		connectivity, err := k.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port, protocol)
		resultsCh <- &probeResult{podFrom, podTo, connectivity, err}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2, port)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		if r.err != nil {
			log.Errorf("unable to perform probe %s -> %s: %v", r.podFrom, r.podTo, r.err)
		}

		// We will receive the connectivity from podFrom to podTo len(ports) times, where
		// ports is the parameter to the Validate method.
		// If it's the first time we observe the connectivity from podFrom to podTo, just
		// store the connectivity we received in reachability matrix.
		// If the connectivity from podFrom to podTo has been observed and is different
		// from the connectivity we received, store Error connectivity in reachability
		// matrix.
		prevConn := reachability.Observed.Get(r.podFrom.String(), r.podTo.String())
		if prevConn == Unknown {
			reachability.Observe(r.podFrom, r.podTo, r.connectivity)
		} else if prevConn != r.connectivity {
			reachability.Observe(r.podFrom, r.podTo, Error)
		}

		if r.connectivity != Connected && reachability.Expected.Get(r.podFrom.String(), r.podTo.String()) == Connected {
			log.Warnf("FAILED CONNECTION FOR ALLOWED PODS %s -> %s:%d:%s !!!! ", r.podFrom, r.podTo, port, protocol)
		}
	}
}

// Validate checks the connectivity between all Pods in both directions with a
// list of ports and a protocol. The connectivity from a Pod to another Pod should
// be consistent across all provided ports. Otherwise, this connectivity will be
// treated as Error.
func (k *KubernetesUtils) Validate(allPods []Pod, reachability *Reachability, ports []int32, protocol v1.Protocol) {
	for _, port := range ports {
		// we do not run all the probes in parallel as we have experienced that on some
		// machines, this can cause a fraction of the probes to always fail, despite the
		// built-in retry (3x) mechanism. Probably because of the large number of probes,
		// each one being executed in its own goroutine. For example, with 9 Pods and for
		// ports 80, 81, 8080, 8081, 8082, 8083, 8084 and 8085, we would end up with
		// potentially 9*9*8 = 648 simultaneous probes.
		k.validateOnePort(allPods, reachability, port, protocol)
	}
}

func (k *KubernetesUtils) Bootstrap(namespaces, pods []string) (*map[string][]string, error) {
	for _, ns := range namespaces {
		_, err := k.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to create/update ns %s", ns)
		}
		for _, pod := range pods {
			log.Infof("Creating/updating Pod '%s/%s'", ns, pod)
			deployment := ns + pod
			_, err := k.CreateOrUpdateDeployment(ns, deployment, 1, map[string]string{"pod": pod, "app": pod})
			if err != nil {
				return nil, errors.WithMessagef(err, "unable to create/update Deployment '%s/%s'", ns, pod)
			}
		}
	}
	var allPods []Pod
	podIPs := make(map[string][]string, len(pods)*len(namespaces))
	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
	for _, pod := range allPods {
		ips, err := k.waitForPodInNamespace(pod.Namespace(), pod.PodName())
		if ips == nil || err != nil {
			return nil, errors.WithMessagef(err, "unable to wait for Pod '%s/%s'", pod.Namespace(), pod.PodName())
		}
		podIPs[pod.String()] = ips
	}

	// Ensure that all the HTTP servers have time to start properly.
	// See https://github.com/antrea-io/antrea/issues/472.
	if err := k.waitForHTTPServers(allPods); err != nil {
		return nil, err
	}

	return &podIPs, nil
}

func (k *KubernetesUtils) Cleanup(namespaces []string) {
	// Cleanup any cluster-scoped resources.
	if err := k.CleanACNPs(); err != nil {
		log.Errorf("Error when cleaning-up ACNPs: %v", err)
	}
	if err := k.CleanCGs(); err != nil {
		log.Errorf("Error when cleaning-up CGs: %v", err)
	}

	for _, ns := range namespaces {
		log.Infof("Deleting test Namespace %s", ns)
		if err := k.clientset.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{}); err != nil {
			log.Errorf("Error when deleting Namespace '%s': %v", ns, err)
		}
	}
}
