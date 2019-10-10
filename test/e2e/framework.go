package e2e

import (
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"okn/test/e2e/providers"
)

const masterNodeName string = "k8s-node-master"

const defaultTimeout time.Duration = 90 * time.Second

const OKNDaemonSet string = "okn-agent"

const testNamespace string = "okn-test"

const podNameSuffixLength int = 8

type ClusterInfo struct {
	numWorkerNodes int
	numNodes       int
	podNetworkCIDR string
}

var clusterInfo ClusterInfo

type TestOptions struct {
	providerName       string
	providerConfigPath string
}

var testOptions TestOptions

var provider providers.ProviderInterface

// Stores the state required for each test case.
type TestData struct {
	clientset kubernetes.Interface
}

func initProvider() error {
	providerFactory := map[string]func(string) (providers.ProviderInterface, error){
		"vagrant": providers.NewVagrantProvider,
	}
	if fn, ok := providerFactory[testOptions.providerName]; ok {
		if newProvider, err := fn(testOptions.providerConfigPath); err != nil {
			return err
		} else {
			provider = newProvider
		}
	} else {
		return fmt.Errorf("unknown provider '%s'", testOptions.providerName)
	}
	return nil
}

func collectClusterInfo() error {
	host, config, err := provider.GetSSHConfig(masterNodeName)
	if err != nil {
		return fmt.Errorf("error when retrieving SSH config for master: %v", err)
	}

	// retrieve cluster CIDR
	if err := func() error {
		cmd := "kubectl cluster-info dump | grep cluster-cidr"
		rc, stdout, _, err := RunSSHCommand(host, config, cmd)
		if err != nil || rc != 0 {
			return fmt.Errorf("error when running the following command on master node: %s", cmd)
		}
		re := regexp.MustCompile(`cluster-cidr=([^"]+)`)
		if matches := re.FindStringSubmatch(stdout); len(matches) == 0 {
			return fmt.Errorf("cannot retrieve cluster CIDR, unexpected kubectl output: %s", stdout)
		} else {
			clusterInfo.podNetworkCIDR = matches[1]
		}
		return nil
	}(); err != nil {
		return err
	}

	// retrieve number of nodes
	if err := func() error {
		cmd := "kubectl get nodes -o name | wc -l | tr -d '\n'"
		rc, stdout, _, err := RunSSHCommand(host, config, cmd)
		if err != nil || rc != 0 {
			return fmt.Errorf("error when running the following command on master node: %s", cmd)
		}
		if count, err := strconv.Atoi(stdout); err != nil {
			return fmt.Errorf("cannot retrieve number of nodes, output is not an integer: %s", stdout)
		} else {
			clusterInfo.numNodes = count
		}
		return nil
	}(); err != nil {
		return err
	}
	clusterInfo.numWorkerNodes = clusterInfo.numNodes - 1

	return nil
}

func (data *TestData) createTestNamespace() error {
	ns := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	if ns, err := data.clientset.CoreV1().Namespaces().Create(&ns); err != nil {
		// Ignore error if the namespace already exists
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("error when creating '%s' namespace: %v", testNamespace, err)
		}
		// When namespace already exists, check phase
		if ns.Status.Phase == v1.NamespaceTerminating {
			return fmt.Errorf("error when creating '%s' namespace: namespace exists but is in 'Terminating' phase", testNamespace)
		}
	}
	return nil
}

// Deletes test namespace and waits for deletiong to actually complete.
func (data *TestData) deleteTestNamespace(timeout time.Duration) error {
	var gracePeriodSeconds int64 = 0
	var propagationPolicy metav1.DeletionPropagation = metav1.DeletePropagationForeground
	deleteOptions := &metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}
	if err := data.clientset.CoreV1().Namespaces().Delete(testNamespace, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// namespace does not exist, we return right away
			return nil
		}
		return fmt.Errorf("error when deleting '%s' namespace: %v", testNamespace, err)
	}
	err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		if ns, err := data.clientset.CoreV1().Namespaces().Get(testNamespace, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				// Success
				return true, nil
			}
			return false, fmt.Errorf("error when getting namespace '%s' after delete: %v", testNamespace, err)
		} else if ns.Status.Phase != v1.NamespaceTerminating {
			return false, fmt.Errorf("deleted namespace '%s' should be in 'Terminating' phase", testNamespace)
		}

		// Keep trying
		return false, nil
	})
	return err
}

// Deploys the OKN DaemonSet using kubectl through an SSH session to the master node.
func (data *TestData) deployOKN() error {
	// TODO: use the k8s apiserver when server side apply is available?
	// See https://kubernetes.io/docs/reference/using-api/api-concepts/#server-side-apply
	host, config, err := provider.GetSSHConfig(masterNodeName)
	if err != nil {
		return fmt.Errorf("error when retrieving SSH config for master: %v", err)
	}
	cmd := fmt.Sprintf("kubectl apply -f ~/okn.yml")
	rc, _, _, err := RunSSHCommand(host, config, cmd)
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying OKN; is okn.yml available on the master node?")
	}
	return nil
}

// Waits for the k8s apiserver to report that the all OKN Pods are availble, i.e. all the nodes have
// one or nore of the OKN daemion Pod running and available.
func (data *TestData) waitForOKNDaemonSetPods(timeout time.Duration) error {
	err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		daemonSet, err := data.clientset.AppsV1().DaemonSets("kube-system").Get(OKNDaemonSet, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error when getting OKN daemonset: %v", err)
		}

		if daemonSet.Status.NumberAvailable == daemonSet.Status.DesiredNumberScheduled {
			// Success
			return true, nil
		}

		// Keep trying
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("okn-agent DaemonSet not ready within %v", defaultTimeout)
	} else if err != nil {
		return err
	}
	return nil
}

// Checks that all the Pods for the CoreDNS deployment are ready. If not, delete all the Pods to
// force them to restart and waits up to timeout for the Pods to become ready.
func (data *TestData) checkCoreDNSPods(timeout time.Duration) error {
	if deployment, err := data.clientset.AppsV1().Deployments("kube-system").Get("coredns", metav1.GetOptions{}); err != nil {
		return fmt.Errorf("error when retrieving CoreDNS deployment: %v", err)
	} else if deployment.Status.UnavailableReplicas == 0 {
		// deployment ready, nothing to do
		return nil
	}

	// restart CoreDNS and wait for all replicas
	var gracePeriodSeconds int64 = 1
	deleteOptions := &metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "k8s-app=kube-dns",
	}
	if err := data.clientset.CoreV1().Pods("kube-system").DeleteCollection(deleteOptions, listOptions); err != nil {
		return fmt.Errorf("error when deleting all CoreDNS Pods: %v", err)
	}
	err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		deployment, err := data.clientset.AppsV1().Deployments("kube-system").Get("coredns", metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error when retrieving CoreDNS deployment: %v", err)
		}
		if deployment.Status.UnavailableReplicas == 0 {
			return true, nil
		}
		// Keep trying
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("some CoreDNS replicas are still unavailable after %v", defaultTimeout)
	} else if err != nil {
		return err
	}
	return nil
}

// Initializes the k8s clientset in the TestData structure.
func (data *TestData) createClient() error {
	kubeconfigPath, err := provider.GetKubeconfigPath()
	if err != nil {
		return fmt.Errorf("error when getting Kubeconfig path: %v", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return fmt.Errorf("error when building kube config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating kubernetes client: %v", err)
	}
	data.clientset = clientset
	return nil
}

// Deletes the OKN DaemonSet; we use cascading deletion, which means all the Pods created by OKN
// will be deleted. After issueing the deletion request, we poll the k8s apiserver to ensure that
// the DaemonSet does not exist any more. This function is a no-op if the OKN DaemonSet does not
// exist at the time the function is called.
func (data *TestData) deleteOKN(timeout time.Duration) error {
	var gracePeriodSeconds int64 = 0
	// Foreground deletion policy ensures that by the time the DaemonSet is deleted, there are
	// no OKN Pods left.
	var propagationPolicy metav1.DeletionPropagation = metav1.DeletePropagationForeground
	deleteOptions := &metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}
	if err := data.clientset.AppsV1().DaemonSets("kube-system").Delete("okn-agent", deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// no OKN DaemonSet running, we return right away
			return nil
		}
		return fmt.Errorf("error when trying to delete OKN DaemonSet: %v", err)
	}
	err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		if _, err := data.clientset.AppsV1().DaemonSets("kube-system").Get(OKNDaemonSet, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				// OKN DaemonSet does not exist any more, success
				return true, nil
			}
			return false, fmt.Errorf("error when trying to get OKN DaemonSet after deletion: %v", err)
		}

		// Keep trying
		return false, nil
	})
	return err
}

// Creates a Pod in the "default" namespace with a single busybox container.
func (data *TestData) createBusyboxPod(name string) error {
	podSpec := v1.PodSpec{
		Containers: []v1.Container{
			{
				Name:            "busybox",
				Image:           "busybox",
				ImagePullPolicy: v1.PullIfNotPresent,
			},
		},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       podSpec,
	}
	if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(pod); err != nil {
		return err
	}
	return nil
}

// Deletes a Pod in the "default" namespace.
func (data *TestData) deletePod(name string) error {
	var gracePeriodSeconds int64 = 0
	deleteOptions := &metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	if err := data.clientset.CoreV1().Pods(testNamespace).Delete(name, deleteOptions); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

type PodCondition func(*v1.Pod) (bool, error)

// Polls the k8s apiserver until the specified Pod is found (in the "default" namespace) and the
// condition predicate is met (or until the provided timeout expires).
func (data *TestData) podWaitFor(timeout time.Duration, name string, condition PodCondition) (*v1.Pod, error) {
	err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		if pod, err := data.clientset.CoreV1().Pods(testNamespace).Get(name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error when getting Pod '%s': %v", name, err)
		} else {
			return condition(pod)
		}
	})
	if err != nil {
		return nil, err
	}
	return data.clientset.CoreV1().Pods(testNamespace).Get(name, metav1.GetOptions{})
}

// Polls the k8s apiserver until the specified Pod is in the "running" state (or until the provided
// timeout expires). The function then returns the IP address assigned to the Pod.
func (data *TestData) podWaitForIP(timeout time.Duration, name string) (string, error) {
	pod, err := data.podWaitFor(timeout, name, func(pod *v1.Pod) (bool, error) {
		return pod.Status.Phase == v1.PodRunning, nil
	})
	if err != nil {
		return "", err
	}
	// According to the k8s API documentation (https://godoc.org/k8s.io/api/core/v1#PodStatus),
	// the PodIP field should only be empty if the Pod has not yet been scheduled, and "running"
	// implies scheduled.
	if pod.Status.PodIP == "" {
		return "", fmt.Errorf("pod is running but has no assigned IP, which should never happen")
	}
	return pod.Status.PodIP, nil
}

// Deletes one "random" Pod belonging to the OKN DaemonSet and measure how long it takes for the Pod
// not to be visible to the client any more.
func (data *TestData) deleteOneOKNPod(gracePeriodSeconds int64, timeout time.Duration) (time.Duration, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=okn",
	}
	pods, err := data.clientset.CoreV1().Pods("kube-system").List(listOptions)
	if err != nil {
		return 0, fmt.Errorf("failed to list OKN Pods: %v", err)
	}
	if len(pods.Items) == 0 {
		return 0, fmt.Errorf("no available Pods")
	}
	onePod := pods.Items[0].Name

	deleteOptions := &metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}

	start := time.Now()
	if err := data.clientset.CoreV1().Pods("kube-system").Delete(onePod, deleteOptions); err != nil {
		return 0, fmt.Errorf("error when deleting Pod: %v", err)
	}

	if err := wait.Poll(1*time.Second, timeout, func() (bool, error) {
		if _, err := data.clientset.CoreV1().Pods("kube-system").Get(onePod, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("error when getting Pod: %v", err)
		}
		// Keep trying
		return false, nil
	}); err != nil {
		return 0, err
	}

	return time.Since(start), nil
}

// Checks that the provided IP address is in the Pod Network CIDR for the cluster.
func validatePodIP(podNetworkCIDR, podIP string) (bool, error) {
	ip := net.ParseIP(podIP)
	if ip == nil {
		return false, fmt.Errorf("'%s' is not a valid IP address", podIP)
	}
	_, cidr, err := net.ParseCIDR(podNetworkCIDR)
	if err != nil {
		return false, fmt.Errorf("podNetworkCIDR '%s' is not a valid CIDR", podNetworkCIDR)
	}
	return cidr.Contains(ip), nil
}

// A DNS-1123 subdomain must consist of lower case alphanumeric characters
var lettersAndDigits = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		randIdx := rand.Intn(len(lettersAndDigits))
		b[i] = lettersAndDigits[randIdx]
	}
	return string(b)
}

func randPodName(prefix string) string {
	return prefix + randSeq(podNameSuffixLength)
}
