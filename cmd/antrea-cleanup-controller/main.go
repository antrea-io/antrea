package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	informer "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	informers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/cleanup/v1beta1"
	listers "github.com/vmware-tanzu/antrea/pkg/client/listers/cleanup/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/signals"
)

const (
	controllerName = "AntreaCleanupController"
	// the controller will stop watching for CRDs and give up when this
	// timeout expires.
	timeout = 60 * time.Second

	antreaNamespace        = "kube-system"
	antreaDaemonSet        = "antrea-agent"
	antreaCleanupDaemonSet = "antrea-cleanup-agent"
)

const (
	ExitCodeSuccess = iota
	ExitCodeFailure
	ExitCodeInterrupted
)

type Controller struct {
	client         crdclientset.Interface
	statusesLister listers.CleanupStatusLister
	statusesSynced cache.InformerSynced
	statuses       map[string]bool
	doneCh         chan struct{}
	target         int
	mutex          sync.Mutex
}

func (c *Controller) processStatus(obj interface{}) {
	nodeName, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Invalid object received by controller")
	}
	// namespace, name, err := cache.SplitMetaNamespaceKey(obj)
	klog.Infof("Received status for Node %s", nodeName)
	newStatus := false

	cleanupStatus, err := c.statusesLister.Get(nodeName)
	if err != nil {
		klog.Errorf("Error when getting CRD for Node %s: %v", nodeName, err)
	} else if !cleanupStatus.Success {
		klog.Warningf("Received negative status for Node %s", nodeName)
	} else {
		newStatus = true
	}

	lenStatuses := 0
	func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.statuses[nodeName] = newStatus
		lenStatuses = len(c.statuses)
	}()

	klog.Infof("statuses: %d/%d", lenStatuses, c.target)

	if lenStatuses >= c.target {
		c.doneCh <- struct{}{}
	}
}

func NewController(
	client crdclientset.Interface,
	statusInformer informers.CleanupStatusInformer,
) *Controller {
	controller := &Controller{
		client:         client,
		statusesLister: statusInformer.Lister(),
		statusesSynced: statusInformer.Informer().HasSynced,
		statuses:       make(map[string]bool),
		doneCh:         make(chan struct{}),
	}

	klog.V(2).Infof("Setting up event handlers")
	statusInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.processStatus,
		UpdateFunc: func(old, new interface{}) {
			controller.processStatus(new)
		},
	})
	return controller
}

func isAntreaRunning(client clientset.Interface) (bool, error) {
	_, err := client.AppsV1().DaemonSets(antreaNamespace).Get(antreaDaemonSet, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("error when getting Antrea DaemonSet: %v", err)
}

func computeCleanupTarget(client clientset.Interface) (int, error) {
	daemonSet, err := client.AppsV1().DaemonSets(antreaNamespace).Get(antreaCleanupDaemonSet, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("error when getting Antrea cleanup DaemonSet: %v", err)
	}
	return int(daemonSet.Status.DesiredNumberScheduled), nil
}

func cleanup() int {
	logs.InitLogs()
	defer logs.FlushLogs()

	klog.Infof("Antrea Cleanup Controller")

	client, crdClient, err := k8s.CreateClients(componentbaseconfig.ClientConnectionConfiguration{})
	if err != nil {
		klog.Errorf("Error creating K8s clients: %v", err)
		return 1
	}

	if running, err := isAntreaRunning(client); err != nil {
		klog.Errorf("Error when checking if Antrea is running: %v", err)
		return 1
	} else if running {
		klog.Errorf("Antrea DaemonSet still running, make sure you delete Antrea with 'kubectl delete -f <path to Antrea YAML>' before performing cleanup")
		return 1
	}

	target, err := computeCleanupTarget(client)
	if err != nil {
		klog.Errorf("Error when querying number of Nodes: %v", err)
		return 1
	}

	informerFactory := informer.NewSharedInformerFactory(crdClient, time.Second*30)
	informer := informerFactory.Cleanup().V1beta1().CleanupStatuses()
	controller := NewController(crdClient, informer)
	controller.target = target

	stopCh := signals.RegisterSignalHandlers()

	informerFactory.Start(stopCh)

	klog.Infof("Waiting for cleanup on %d Nodes", target)

	complete := func() int {
		controller.mutex.Lock()
		defer controller.mutex.Unlock()
		errorCount := 0
		for _, status := range controller.statuses {
			if !status {
				errorCount += 1
			}
		}
		klog.Infof("statuses: %d/%d - error count: %d", len(controller.statuses), controller.target, errorCount)
		if errorCount != 0 {
			return ExitCodeFailure
		}
		return ExitCodeSuccess
	}

	select {
	case <-stopCh:
		klog.Errorf("Received exit signal before completion")
		return ExitCodeInterrupted
	case <-controller.doneCh:
		klog.Infof("Controller work is done")
		return complete()
	case <-time.After(timeout):
		klog.Warningf("Timeout while waiting for enough Nodes to report status")
		return complete()
	}

	return ExitCodeSuccess
}

func main() {
	os.Exit(cleanup())
}
