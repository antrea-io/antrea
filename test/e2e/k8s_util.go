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
	"bytes"
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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	secClient "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/security/v1alpha1"
)

type Kubernetes struct {
	data           *TestData
	podCache       map[string][]v1.Pod
	ClientSet      *kubernetes.Clientset
	SecurityClient *secClient.SecurityV1alpha1Client
}

func NewKubernetes(data *TestData) (*Kubernetes, error) {
	clientSet, secClienSet := data.getClients()
	return &Kubernetes{
		data:           data,
		podCache:       map[string][]v1.Pod{},
		ClientSet:      clientSet.(*kubernetes.Clientset),
		SecurityClient: secClienSet.(*secClient.SecurityV1alpha1Client),
	}, nil
}

// GetPod returns a pod with the matching namespace and name
func (k *Kubernetes) GetPod(ns string, name string) (*v1.Pod, error) {
	pods, err := k.getPodsUncached(ns, "pod", name)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get pod %s/%s", ns, name)
	}
	if len(pods) == 0 {
		return nil, nil
	}
	return &pods[0], nil
}

func (k *Kubernetes) getPodsUncached(ns string, key, val string) ([]v1.Pod, error) {
	v1PodList, err := k.ClientSet.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%v=%v", key, val),
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to list pods")
	}
	return v1PodList.Items, nil
}

// GetPods returns an array of all pods in the given namespace having a k/v label pair.
func (k *Kubernetes) GetPods(ns string, key string, val string) ([]v1.Pod, error) {
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

// Probe execs into a pod and checks its connectivity to another pod.  Of course it assumes
// that the target pod is serving on the input port, and also that wget is installed.  For perf it uses
// spider rather then actually getting the full contents.
func (k *Kubernetes) Probe(ns1, pod1, ns2, pod2 string, port int) (bool, error) {
	fromPods, err := k.GetPods(ns1, "pod", pod1)
	if err != nil {
		return false, errors.WithMessagef(err, "unable to get pods from ns %s", ns1)
	}
	if len(fromPods) == 0 {
		return false, errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod1, ns1))
	}
	fromPod := fromPods[0]

	toPods, err := k.GetPods(ns2, "pod", pod2)
	if err != nil {
		return false, errors.WithMessagef(err, "unable to get pods from ns %s", ns2)
	}
	if len(toPods) == 0 {
		return false, errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod2, ns2))
	}
	toPod := toPods[0]

	toIP := toPod.Status.PodIP

	// There seems to be an issue when running Antrea in Kind where tunnel traffic is dropped at
	// first. This leads to the first test being run consistently failing. To avoid this issue
	// until it is resolved, we try to connect 3 times.
	// See https://github.com/vmware-tanzu/antrea/issues/467.
	cmd := []string{
		"/bin/sh",
		"-c",
		// 3 tries, timeout is 1 second
		fmt.Sprintf("for i in $(seq 1 3); do ncat -vz -w 1 %s %d && exit 0 || true; done; exit 1", toIP, port),
	}
	// HACK: inferring container name as c80, c81, etc, for simplicity.
	containerName := fmt.Sprintf("c%v", port)
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", fromPod.Name, containerName, fromPod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.data.runCommandFromPod(fromPod.Namespace, fromPod.Name, containerName, cmd)
	if err != nil {
		// log this error as trace since may be an expected failure
		log.Tracef("%s/%s -> %s/%s: error when running command: err - %v /// stdout - %s /// stderr - %s", ns1, pod1, ns2, pod2, err, stdout, stderr)
		// do not return an error
		return false, nil
	}
	return true, nil
}

// ExecuteRemoteCommand executes a remote shell command on the given pod
// returns the output from stdout and stderr
func (k *Kubernetes) ExecuteRemoteCommand(pod v1.Pod, cname string, command []string) (string, string, error) {
	kubeCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)
	restCfg, err := kubeCfg.ClientConfig()
	if err != nil {
		return "", "", errors.WithMessagef(err, "unable to get rest config from kube config")
	}
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	request := k.ClientSet.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("pods").
		Name(pod.Name).SubResource("exec").VersionedParams(&v1.PodExecOptions{
		Container: cname,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false},
		scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restCfg, "POST", request.URL())
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to create SPDYExecutor")
	}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	if err != nil {
		return buf.String(), errBuf.String(), err
	}
	return buf.String(), errBuf.String(), nil
}

// CreateOrUpdateNamespace is a convenience function for idempotent setup of namespaces
func (k *Kubernetes) CreateOrUpdateNamespace(n string, labels map[string]string) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n,
			Labels: labels,
		},
	}
	nsr, err := k.ClientSet.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err == nil {
		log.Infof("created namespace %s", n)
		return nsr, nil
	}

	log.Debugf("unable to create namespace %s, let's try updating it instead (error: %s)", ns.Name, err)
	nsr, err = k.ClientSet.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("unable to update namespace %s: %s", ns, err)
	}

	return nsr, err
}

// CreateOrUpdateDeployment is a convenience function for idempotent setup of deployments
func (k *Kubernetes) CreateOrUpdateDeployment(ns, deploymentName string, replicas int32, labels map[string]string) (*appsv1.Deployment, error) {
	zero := int64(0)
	log.Infof("creating/updating deployment %s in ns %s", deploymentName, ns)
	makeContainerSpec := func(port int32) v1.Container {
		return v1.Container{
			Name:            fmt.Sprintf("c%d", port),
			ImagePullPolicy: v1.PullIfNotPresent,
			Image:           "antrea/netpol-test:latest",
			// "-k" for persistent server
			Command:         []string{"ncat", "-lk", "-p", fmt.Sprintf("%d", port)},
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
						makeContainerSpec(80), makeContainerSpec(81),
					},
				},
			},
		},
	}

	d, err := k.ClientSet.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err == nil {
		log.Infof("created deployment %s in namespace %s", d.Name, ns)
		return d, nil
	}

	log.Debugf("unable to create deployment %s in ns %s, let's try update instead", deployment.Name, ns)
	d, err = k.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), d, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("unable to update deployment %s in ns %s: %s", deployment.Name, ns, err)
	}
	return d, err
}

// CleanNetworkPolicies is a convenience function for deleting network policies before startup of any new test.
func (k *Kubernetes) CleanNetworkPolicies(namespaces []string) error {
	for _, ns := range namespaces {
		l, err := k.ClientSet.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list network policies in ns %s", ns)
		}
		for _, np := range l.Items {
			log.Infof("deleting network policy %s in ns %s", np.Name, ns)
			err = k.ClientSet.NetworkingV1().NetworkPolicies(np.Namespace).Delete(context.TODO(), np.Name, metav1.DeleteOptions{})
			if err != nil {
				return errors.Wrapf(err, "unable to delete network policy %s", np.Name)
			}
		}
	}
	return nil
}

// CreateOrUpdateNetworkPolicy is a convenience function for updating/creating netpols. Updating is important since
// some tests update a network policy to confirm that mutation works with a CNI.
func (k *Kubernetes) CreateOrUpdateNetworkPolicy(ns string, netpol *v1net.NetworkPolicy) (*v1net.NetworkPolicy, error) {
	log.Infof("creating/updating network policy %s in ns %s", netpol.Name, ns)
	netpol.ObjectMeta.Namespace = ns
	np, err := k.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), netpol, metav1.UpdateOptions{})
	if err == nil {
		return np, err
	}

	log.Debugf("unable to update network policy %s in ns %s, let's try creating it instead (error: %s)", netpol.Name, ns, err)
	np, err = k.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), netpol, metav1.CreateOptions{})
	if err != nil {
		log.Debugf("unable to create network policy: %s", err)
	}
	return np, err
}

// CleanCNPs is a convenience function for deleting ClusterNetworkPolicies before startup of any new test.
func (k *Kubernetes) CleanCNPs() error {
	l, err := k.SecurityClient.ClusterNetworkPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to list ClusterNetworkPolicies")
	}
	for _, cnp := range l.Items {
		log.Infof("deleting ClusterNetworkPolicies %s", cnp.Name)
		err = k.SecurityClient.ClusterNetworkPolicies().Delete(context.TODO(), cnp.Name, metav1.DeleteOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to delete ClusterNetworkPolicy %s", cnp.Name)
		}
	}
	return nil
}

// CreateOrUpdateCNP is a convenience function for updating/creating ClusterNetworkPolicies.
func (k *Kubernetes) CreateOrUpdateCNP(cnp *secv1alpha1.ClusterNetworkPolicy) (*secv1alpha1.ClusterNetworkPolicy, error) {
	log.Infof("creating/updating ClusterNetworkPolicy %s", cnp.Name)
	cnpReturned, err := k.SecurityClient.ClusterNetworkPolicies().Get(context.TODO(), cnp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("creating ClusterNetworkPolicy %s", cnp.Name)
		cnp, err = k.SecurityClient.ClusterNetworkPolicies().Create(context.TODO(), cnp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("unable to create ClusterNetworkPolicy: %s", err)
		}
		return cnp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("ClusterNetworkPolicy with name %s already exists, updating", cnp.Name)
		cnp, err = k.SecurityClient.ClusterNetworkPolicies().Update(context.TODO(), cnp, metav1.UpdateOptions{})
		return cnp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating ClusterNetworkPolicy %s", cnp.Name)
}

func (k *Kubernetes) waitForPodInNamespace(ns string, pod string) (*string, error) {
	log.Infof("waiting for pod %s/%s", ns, pod)
	for {
		k8sPod, err := k.GetPod(ns, pod)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to get pod %s/%s", ns, pod)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return nil, errors.WithMessagef(err, "unable to get IP of pod %s/%s", ns, pod)
			} else {
				log.Debugf("IP of pod %s/%s is: %s", ns, pod, k8sPod.Status.PodIP)
			}

			log.Debugf("pod running: %s/%s", ns, pod)
			podIP := k8sPod.Status.PodIP
			return &podIP, nil
		}
		log.Infof("pod %s/%s not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func (k *Kubernetes) waitForHTTPServers(allPods []Pod) error {
	const maxTries = 10
	const sleepInterval = 1 * time.Second
	log.Infof("waiting for HTTP servers (ports 80 and 81) to become ready")
	var wrong int
	for i := 0; i < maxTries; i++ {
		reachability := NewReachability(allPods, true)
		k.Validate(allPods, reachability, 80)
		k.Validate(allPods, reachability, 81)
		_, wrong, _ = reachability.Summary()
		if wrong == 0 {
			log.Infof("all HTTP servers are ready")
			return nil
		}
		log.Debugf("%d HTTP servers not ready", wrong)
		time.Sleep(sleepInterval)
	}
	return errors.Errorf("after %d tries, %d HTTP servers are not ready", maxTries, wrong)
}

func (k *Kubernetes) Validate(allPods []Pod, reachability *Reachability, port int) {
	type probeResult struct {
		podFrom   Pod
		podTo     Pod
		connected bool
		err       error
	}
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo Pod) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		connected, err := k.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port)
		resultsCh <- &probeResult{podFrom, podTo, connected, err}
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
		reachability.Observe(r.podFrom, r.podTo, r.connected)
		if !r.connected && reachability.Expected.Get(r.podFrom.String(), r.podTo.String()) {
			log.Warnf("FAILED CONNECTION FOR WHITELISTED PODS %s -> %s !!!! ", r.podFrom, r.podTo)
		}
	}
}

func (k *Kubernetes) Bootstrap(namespaces, pods []string) (*map[string]string, error) {
	for _, ns := range namespaces {
		_, err := k.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to create/update ns %s", ns)
		}
		for _, pod := range pods {
			log.Infof("creating/updating pod %s/%s", ns, pod)
			_, err := k.CreateOrUpdateDeployment(ns, ns+pod, 1, map[string]string{"pod": pod})
			if err != nil {
				return nil, errors.WithMessagef(err, "unable to create/update deployment %s/%s", ns, pod)
			}
		}
	}
	var allPods []Pod
	podIPs := make(map[string]string, len(pods)*len(namespaces))
	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
	for _, pod := range allPods {
		ip, err := k.waitForPodInNamespace(pod.Namespace(), pod.PodName())
		if ip == nil || err != nil {
			return nil, errors.WithMessagef(err, "unable to wait for pod %s/%s", pod.Namespace(), pod.PodName())
		}
		podIPs[pod.String()] = *ip
	}

	// Ensure that all the HTTP servers have time to start properly.
	// See https://github.com/vmware-tanzu/antrea/issues/472.
	if err := k.waitForHTTPServers(allPods); err != nil {
		return nil, err
	}

	return &podIPs, nil
}

func (k *Kubernetes) Cleanup(namespaces []string) error {
	if err := k.CleanCNPs(); err != nil {
		return err
	}
	for _, ns := range namespaces {
		log.Infof("Deleting test namespace %s", ns)
		if err := k.ClientSet.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return nil
}
