package packetsampling

import (
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"time"

	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/client/clientset/versioned"
	"k8s.io/client-go/util/workqueue"
)

const (
	controllerName = "PacketSamplingController"

	// set resyncPeriod to 0 to disable resyncing
	resyncPeriod time.Duration = 0

	// Default number of workers processing packetsampling request.
	defaultWorkers = 4

	// reason for timeout
	samplingTimeout = "PacketSampling timeout"

	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketSamplingTimeout)
)

var (
	timeoutCheckInterval = 10 * time.Second
)

type Controller struct {
	client                     versiond.Interface
	podInformer                coreinformers.PodInformer
	podLister                  corelisters.PodLister
	packetSamplingInformer     crdinformers.PacketSamplingInformer
	packetSamplingLister       crdlisters.PacketSamplingLister
	packetSamplingListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface
}

func NewPacketSamplingController(client versiond.Interface, podInformer coreinformers.PodInformer, packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {

	c := &Controller{
		client:                     client,
		podInformer:                podInformer,
		packetSamplingInformer:     packetSamplingInformer,
		packetSamplingLister:       packetSamplingInformer.Lister(),
		packetSamplingListerSynced: packetSamplingInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "packetsampling"),
	}

	// add handlers
}
