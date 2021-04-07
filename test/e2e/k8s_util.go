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
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	legacycorev1a2 "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacysecv1alpha1 "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
)

type KubernetesUtils struct {
	*TestData
	podCache map[string][]v1.Pod
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
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get Pod in Namespace %s with label pod=%s", ns, name)
	}
	if len(pods) == 0 {
		return nil, nil
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

// Probe execs into a Pod and checks its connectivity to another Pod.  Of course it assumes
// that the target Pod is serving on the input port, and also that agnhost is installed.
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

		// There seems to be an issue when running Antrea in Kind where tunnel traffic is dropped at
		// first. This leads to the first test being run consistently failing. To avoid this issue
		// until it is resolved, we try to connect 3 times.
		// See https://github.com/vmware-tanzu/antrea/issues/467.
		cmd := []string{
			"/bin/sh",
			"-c",
		}
		switch protocol {
		case v1.ProtocolTCP:
			cmd = append(cmd, fmt.Sprintf("for i in $(seq 1 3); do /agnhost connect %s:%d --timeout=1s --protocol=tcp && exit 0 || true; done; exit 1", toIP, port))
		case v1.ProtocolUDP:
			cmd = append(cmd, fmt.Sprintf("for i in $(seq 1 3); do /agnhost connect %s:%d --timeout=1s --protocol=udp && exit 0 || true; done; exit 1", toIP, port))
		case v1.ProtocolSCTP:
			cmd = append(cmd, fmt.Sprintf("for i in $(seq 1 3); do /agnhost connect %s:%d --timeout=1s --protocol=sctp && exit 0 || true; done; exit 1", toIP, port))
		}
		// HACK: inferring container name as c80, c81, etc, for simplicity.
		containerName := fmt.Sprintf("c%v", port)
		log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", fromPod.Name, containerName, fromPod.Namespace, strings.Join(cmd, " "))
		stdout, stderr, err := k.runCommandFromPod(fromPod.Namespace, fromPod.Name, containerName, cmd)
		var curConnectivity PodConnectivityMark
		if err != nil {
			// log this error as trace since may be an expected failure
			log.Tracef("%s/%s -> %s/%s: error when running command: err - %v /// stdout - %s /// stderr - %s", ns1, pod1, ns2, pod2, err, stdout, stderr)
			// do not return an error
			if strings.Contains(stderr, "TIMEOUT") {
				curConnectivity = Dropped
			} else {
				curConnectivity = Rejected
			}
		} else {
			curConnectivity = Connected
		}

		if connectivity == Unknown {
			connectivity = curConnectivity
		} else if connectivity != curConnectivity {
			return Error, nil
		}
	}
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
	nsr, err := k.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Created Namespace %s", n)
		return nsr, nil
	}

	log.Debugf("Unable to create Namespace %s, let's try updating it instead (error: %s)", ns.Name, err)
	nsr, err = k.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("Unable to update Namespace %s: %s", ns, err)
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
			Image:           "k8s.gcr.io/e2e-test-images/agnhost:2.29",
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

// CreateOrUpdateCG is a convenience function for idempotent setup of ClusterGroups
func (k *KubernetesUtils) CreateOrUpdateCG(cg *crdv1alpha2.ClusterGroup) (*crdv1alpha2.ClusterGroup, error) {
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

// CreateCG is a convenience function for creating an Antrea ClusterGroup by name and selector.
func (k *KubernetesUtils) CreateCG(name string, pSelector, nSelector *metav1.LabelSelector, ipBlock *crdv1alpha1.IPBlock) (*crdv1alpha2.ClusterGroup, error) {
	log.Infof("Creating clustergroup %s", name)
	_, err := k.crdClient.CrdV1alpha2().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		cg := &crdv1alpha2.ClusterGroup{
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
		if ipBlock != nil {
			cg.Spec.IPBlock = ipBlock
		}
		cg, err = k.crdClient.CrdV1alpha2().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
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

// DeleteCG is a convenience function for deleting ClusterGroup by name.
func (k *KubernetesUtils) DeleteCG(name string) error {
	log.Infof("Deleting ClusterGroup %s", name)
	err := k.crdClient.CrdV1alpha2().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete ClusterGroup %s", name)
	}
	return nil
}

// CleanCGs is a convenience function for deleting all ClusterGroups in the cluster.
func (k *KubernetesUtils) CleanCGs() error {
	l, err := k.crdClient.CrdV1alpha2().ClusterGroups().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list ClusterGroups")
	}
	for _, cg := range l.Items {
		if err := k.DeleteCG(cg.Name); err != nil {
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
	log.Infof("Waiting for HTTP servers (ports 80, 81, 5000 and 8080:8085) to become ready")
	var wrong int
	for i := 0; i < maxTries; i++ {
		reachability := NewReachability(allPods, Connected)
		k.Validate(allPods, reachability, 80, v1.ProtocolTCP)
		k.Validate(allPods, reachability, 80, v1.ProtocolUDP)
		k.Validate(allPods, reachability, 80, v1.ProtocolSCTP)
		k.Validate(allPods, reachability, 81, v1.ProtocolTCP)
		k.Validate(allPods, reachability, 81, v1.ProtocolUDP)
		k.Validate(allPods, reachability, 81, v1.ProtocolSCTP)
		for j := 8080; j < 8086; j++ {
			k.Validate(allPods, reachability, int32(j), v1.ProtocolTCP)
		}
		_, wrong, _ = reachability.Summary()
		if wrong == 0 {
			log.Infof("All HTTP servers are ready")
			return nil
		}
		log.Debugf("%d HTTP servers not ready", wrong)
		time.Sleep(defaultInterval)
	}
	return errors.Errorf("after %d tries, %d HTTP servers are not ready", maxTries, wrong)
}

func (k *KubernetesUtils) Validate(allPods []Pod, reachability *Reachability, port int32, protocol v1.Protocol) {
	type probeResult struct {
		podFrom      Pod
		podTo        Pod
		connectivity PodConnectivityMark
		err          error
	}
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo Pod) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		connectivity, err := k.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port, protocol)
		resultsCh <- &probeResult{podFrom, podTo, connectivity, err}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		if r.err != nil {
			log.Errorf("unable to perform probe %s -> %s: %v", r.podFrom, r.podTo, r.err)
		}
		reachability.Observe(r.podFrom, r.podTo, r.connectivity)
		if r.connectivity != Connected && reachability.Expected.Get(r.podFrom.String(), r.podTo.String()) == Connected {
			log.Warnf("FAILED CONNECTION FOR ALLOWED PODS %s -> %s !!!! ", r.podFrom, r.podTo)
		}
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
	// See https://github.com/vmware-tanzu/antrea/issues/472.
	if err := k.waitForHTTPServers(allPods); err != nil {
		return nil, err
	}

	return &podIPs, nil
}

func (k *KubernetesUtils) Cleanup(namespaces []string) error {
	// Cleanup any cluster-scoped resources.
	if err := k.CleanACNPs(); err != nil {
		return err
	}
	if err := k.CleanCGs(); err != nil {
		return err
	}

	for _, ns := range namespaces {
		log.Infof("Deleting test Namespace %s", ns)
		if err := k.clientset.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// CreateOrUpdateANP is a convenience function for updating/creating Antrea NetworkPolicies.
func (k *KubernetesUtils) CreateOrUpdateLegacyANP(anp *legacysecv1alpha1.NetworkPolicy) (*legacysecv1alpha1.NetworkPolicy, error) {
	log.Infof("Creating/updating legacy Antrea NetworkPolicy %s/%s", anp.Namespace, anp.Name)
	cnpReturned, err := k.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating legacy Antrea NetworkPolicy %s", anp.Name)
		anp, err = k.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create legacy Antrea NetworkPolicy: %s", err)
		}
		return anp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("Legacy Antrea NetworkPolicy with name %s already exists, updating", anp.Name)
		anp, err = k.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Update(context.TODO(), anp, metav1.UpdateOptions{})
		return anp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating legacy Antrea NetworkPolicy %s", anp.Name)
}

// DeleteLegacyANP is a convenience function for deleting ANP by name and Namespace.
func (k *KubernetesUtils) DeleteLegacyANP(ns, name string) error {
	log.Infof("Deleting legacy Antrea NetworkPolicy '%s/%s'", ns, name)
	err := k.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete legacy Antrea NetworkPolicy %s", name)
	}
	return nil
}

// CleanLegacyANPs is a convenience function for deleting all Antrea NetworkPolicies in provided namespaces.
func (k *KubernetesUtils) CleanLegacyANPs(namespaces []string) error {
	for _, ns := range namespaces {
		l, err := k.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list legacy Antrea NetworkPolicies in ns %s", ns)
		}
		for _, anp := range l.Items {
			if err = k.DeleteLegacyANP(anp.Namespace, anp.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateLegacyTier is a convenience function for creating a legacy Antrea Policy Tier by name and priority.
func (k *KubernetesUtils) CreateNewLegacyTier(name string, tierPriority int32) (*legacysecv1alpha1.Tier, error) {
	log.Infof("Creating legacy tier %s", name)
	_, err := k.legacyCrdClient.SecurityV1alpha1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		tr := &legacysecv1alpha1.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       crdv1alpha1.TierSpec{Priority: tierPriority},
		}
		tr, err = k.legacyCrdClient.SecurityV1alpha1().Tiers().Create(context.TODO(), tr, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create legacy tier %s: %s", name, err)
		}
		return tr, err
	}
	return nil, fmt.Errorf("legacy tier with name %s already exists", name)
}

// UpdateLegacyTier is a convenience function for updating a legacy Antrea Policy Tier.
func (k *KubernetesUtils) UpdateLegacyTier(tier *legacysecv1alpha1.Tier) (*legacysecv1alpha1.Tier, error) {
	log.Infof("Updating legacy tier %s", tier.Name)
	updatedTier, err := k.legacyCrdClient.SecurityV1alpha1().Tiers().Update(context.TODO(), tier, metav1.UpdateOptions{})
	return updatedTier, err
}

// DeleteLegacyTier is a convenience function for deleting a legacy Antrea Policy Tier with specific name.
func (k *KubernetesUtils) DeleteLegacyTier(name string) error {
	_, err := k.legacyCrdClient.SecurityV1alpha1().Tiers().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to get legacy tier %s", name)
	}
	log.Infof("Deleting legacy tier %s", name)
	if err = k.legacyCrdClient.SecurityV1alpha1().Tiers().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		return errors.Wrapf(err, "unable to delete legacy tier %s", name)
	}
	return nil
}

// CreateLegacyCG is a convenience function for creating a legacy Antrea ClusterGroup by name and selector.
func (k *KubernetesUtils) CreateLegacyCG(name string, pSelector, nSelector *metav1.LabelSelector, ipBlock *crdv1alpha1.IPBlock) (*legacycorev1a2.ClusterGroup, error) {
	log.Infof("Creating legacy clustergroup %s", name)
	_, err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		cg := &legacycorev1a2.ClusterGroup{
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
		if ipBlock != nil {
			cg.Spec.IPBlock = ipBlock
		}
		cg, err = k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create legacy ClusterGroup %s: %s", name, err)
		}
		return cg, err
	}
	return nil, fmt.Errorf("legacy ClusterGroup with name %s already exists", name)
}

// CreateOrUpdateLegacyCG is a convenience function for idempotent setup of legacy ClusterGroups
func (k *KubernetesUtils) CreateOrUpdateLegacyCG(cg *legacycorev1a2.ClusterGroup) (*legacycorev1a2.ClusterGroup, error) {
	log.Infof("Creating/updating legacy ClusterGroup %s", cg.Name)
	cgReturned, err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Get(context.TODO(), cg.Name, metav1.GetOptions{})
	if err != nil {
		cgr, err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Create(context.TODO(), cg, metav1.CreateOptions{})
		if err != nil {
			log.Infof("Unable to create legacy ClusterGroup %s: %v", cg.Name, err)
			return nil, err
		}
		return cgr, nil
	} else if cgReturned.Name != "" {
		log.Debugf("Legacy ClusterGroup with name %s already exists, updating", cg.Name)
		cgReturned.Spec = cg.Spec
		cgr, err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Update(context.TODO(), cgReturned, metav1.UpdateOptions{})
		return cgr, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating legacy ClusterGroup %s", cg.Name)
}

// DeleteLegacyCG is a convenience function for deleting legacy ClusterGroup by name.
func (k *KubernetesUtils) DeleteLegacyCG(name string) error {
	log.Infof("Deleting ClusterGroup %s", name)
	err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete legacy ClusterGroup %s", name)
	}
	return nil
}

// CleanCGs is a convenience function for deleting all ClusterGroups in the cluster.
func (k *KubernetesUtils) CleanLegacyCGs() error {
	l, err := k.legacyCrdClient.CoreV1alpha2().ClusterGroups().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list legacy ClusterGroups")
	}
	for _, cg := range l.Items {
		if err := k.DeleteLegacyCG(cg.Name); err != nil {
			return err
		}
	}
	return nil
}

// CreateOrUpdateLegacyACNP is a convenience function for updating/creating AntreaClusterNetworkPolicies.
func (k *KubernetesUtils) CreateOrUpdateLegacyACNP(cnp *legacysecv1alpha1.ClusterNetworkPolicy) (*legacysecv1alpha1.ClusterNetworkPolicy, error) {
	log.Infof("Creating/updating legacy ClusterNetworkPolicy %s", cnp.Name)
	cnpReturned, err := k.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), cnp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating legacy ClusterNetworkPolicy %s", cnp.Name)
		cnp, err = k.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Create(context.TODO(), cnp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create legacy ClusterNetworkPolicy: %s", err)
		}
		return cnp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("Legacy ClusterNetworkPolicy with name %s already exists, updating", cnp.Name)
		cnpReturned.Spec = cnp.Spec
		cnp, err = k.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Update(context.TODO(), cnpReturned, metav1.UpdateOptions{})
		return cnp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating legacy ClusterNetworkPolicy %s", cnp.Name)
}

// DeleteLegacyACNP is a convenience function for deleting ACNP by name.
func (k *KubernetesUtils) DeleteLegacyACNP(name string) error {
	log.Infof("Deleting AntreaClusterNetworkPolicies %s", name)
	err := k.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to delete legacy ClusterNetworkPolicy %s", name)
	}
	return nil
}

// CleanLegacyACNPs is a convenience function for deleting all Antrea ClusterNetworkPolicies in the cluster.
func (k *KubernetesUtils) CleanLegacyACNPs() error {
	l, err := k.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list legacy AntreaClusterNetworkPolicies")
	}
	for _, cnp := range l.Items {
		if err = k.DeleteLegacyACNP(cnp.Name); err != nil {
			return err
		}
	}
	return nil
}

func (k *KubernetesUtils) LegacyCleanup(namespaces []string) error {
	// Cleanup any cluster-scoped resources.
	if err := k.CleanLegacyACNPs(); err != nil {
		return err
	}
	if err := k.CleanLegacyCGs(); err != nil {
		return err
	}
	for _, ns := range namespaces {
		log.Infof("Deleting test Namespace %s", ns)
		if err := k.clientset.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return nil
}
