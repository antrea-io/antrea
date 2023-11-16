package packetsampling

import (
	"net"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/time/rate"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	controllerName               = "AntreaAgentPacketSamplingController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4
)

const (
	samplingStatusUpdatePeriod = 10 * time.Second
	packetDirectoryUnix        = "/tmp/packetsampling/packets"
	packetDirectoryWindows     = "C:\\packetsampling\\packets"
)

var packetDirectory = getPacketDirectory()

// TODO: refactor this part.
func getPacketDirectory() string {
	if runtime.GOOS == "windows" {
		return packetDirectoryWindows
	} else {
		return getPacketDirectory()
	}
}

type packetSamplingState struct {
	shouldSyncPackets     bool
	numCapturedPackets    int32
	maxNumCapturedPackets int32
	updateRateLimiter     *rate.Limiter

	uid          string
	pcapngFile   *os.File
	pcapngWriter *pcapgo.NgWriter
}

type Controller struct {
	kubeClient             clientset.Interface
	serviceLister          corelisters.ServiceLister
	serviceListerSynced    cache.InformerSynced
	packetSamplingClient   clientsetversioned.Interface
	packetSamplingInformer crdinformers.PacketSamplingInformer
	packetSamplingLister   crdlisters.PacketSamplingLister

	packetSamplingSynced cache.InformerSynced
	ovsBridgeClient      ovsconfig.OVSBridgeClient
	ofClient             openflow.Client

	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	egressQuerier        querier.EgressQuerier

	interfaceStore interfacestore.InterfaceStore
	networkConfig  *config.NetworkConfig
	nodeConfig     *config.NodeConfig
	serviceCIDR    *net.IPNet

	queue                       workqueue.RateLimitingInterface
	runningPacketSamplingsMutex sync.RWMutex

	runningPacketSamplings map[uint8]*packetSamplingState
}

func NewPacketSamplingController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {
	c := &Controller{
		kubeClient: kubeClient,
	}

	packetSamplingInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketSampling,
		UpdateFunc: c.updatePacketSampling,
		DeleteFunc: c.deletePacketSampling,
	}, resyncPeriod)

	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryTF), c)

	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		c.serviceLister = informerFactory.Core().V1().Services().Lister()
		c.serviceListerSynced = informerFactory.Core().V1().Services().Informer().HasSynced
	}
	return c

}

func (c *Controller) enqueuePacketSampling(ps *crdv1alpha1.PacketSampling) {
	c.queue.Add(ps.Name)
}

func (c *Controller) addPacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s ADD event", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) updatePacketSampling(_, obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s UPDATE EVENT", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) deletePacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s DELETE event", ps.Name)

	err := deletePcapngFile(ps.Status.UID)
	if err != nil {
		klog.ErrorS(err, "Couldn't delete pcapng file")

	}
	c.enqueuePacketSampling(ps)

}

func deletePcapngFile(uid string) error {
	return os.Remove(uidToPath(uid))
}

func uidToPath(uid string) string {
	return path.Join(packetDirectory, uid+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketSamplingItem() {

	}
}

func (c *Controller) processPacketSamplingItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncPacketSampling(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.Errorf("Error syncing PacketSampling %s, existing. Error: %v", key, err)
	}
	return true
}

func (c *Controller) syncPacketSampling(psName string) error {
	startTime := time.Now()

	defer func() {
		klog.V(4).Infof("Finished syncing PacketSampling for %s. (%v)", psName, time.Since(startTime))
	}()

	ps, err := c.packetSamplingLister.Get(psName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPakcetSampling(psName)
			return nil

		}
		return err
	}

	switch ps.Status.Phase {

	}

}
