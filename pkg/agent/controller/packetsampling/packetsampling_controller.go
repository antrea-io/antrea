// Copyright 2024 Antrea Authors.
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

package packetsampling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/protocol"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ftp"
)

type StorageProtocolType string

const (
	sftpProtocol StorageProtocolType = "sftp"
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
)

var (
	packetDirectory = getPacketDirectory()
	defaultFS       = afero.NewOsFs()
)

func getPacketDirectory() string {
	return filepath.Join(os.TempDir(), "packetsampling", "packets")
}

type packetSamplingState struct {
	name                  string
	tag                   int8
	shouldSyncPackets     bool
	numCapturedPackets    int32
	maxNumCapturedPackets int32
	updateRateLimiter     *rate.Limiter
	uid                   string
	pcapngFile            afero.File
	pcapngWriter          *pcapgo.NgWriter
	receiverOnly          bool
	isSender              bool
}

type Controller struct {
	kubeClient                  clientset.Interface
	crdClient                   clientsetversioned.Interface
	serviceLister               corelisters.ServiceLister
	serviceListerSynced         cache.InformerSynced
	endpointLister              corelisters.EndpointsLister
	endpointSynced              cache.InformerSynced
	packetSamplingInformer      crdinformers.PacketSamplingInformer
	packetSamplingLister        crdlisters.PacketSamplingLister
	packetSamplingSynced        cache.InformerSynced
	ofClient                    openflow.Client
	interfaceStore              interfacestore.InterfaceStore
	networkConfig               *config.NetworkConfig
	nodeConfig                  *config.NodeConfig
	serviceCIDR                 *net.IPNet
	queue                       workqueue.RateLimitingInterface
	runningPacketSamplingsMutex sync.RWMutex
	runningPacketSamplings      map[int8]*packetSamplingState
	enableAntreaProxy           bool
	sftpUploader                ftp.UpLoader
}

func NewPacketSamplingController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointInformer coreinformers.EndpointsInformer,
	packetSamplingInformer crdinformers.PacketSamplingInformer,
	client openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	networkConfig *config.NetworkConfig,
	nodeConfig *config.NodeConfig,
	serviceCIDR *net.IPNet,
	enableAntreaProxy bool,
) *Controller {
	c := &Controller{
		kubeClient:             kubeClient,
		crdClient:              crdClient,
		packetSamplingInformer: packetSamplingInformer,
		packetSamplingLister:   packetSamplingInformer.Lister(),
		packetSamplingSynced:   packetSamplingInformer.Informer().HasSynced,
		ofClient:               client,
		interfaceStore:         interfaceStore,
		networkConfig:          networkConfig,
		nodeConfig:             nodeConfig,
		serviceCIDR:            serviceCIDR,
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "packetsampling"),
		runningPacketSamplings: make(map[int8]*packetSamplingState),
		sftpUploader:           &ftp.SftpUploader{},
		enableAntreaProxy:      enableAntreaProxy,
	}

	packetSamplingInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketSampling,
		UpdateFunc: c.updatePacketSampling,
		DeleteFunc: c.deletePacketSampling,
	}, resyncPeriod)

	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryPS), c)

	if c.enableAntreaProxy {
		c.serviceLister = serviceInformer.Lister()
		c.serviceListerSynced = serviceInformer.Informer().HasSynced
		c.endpointLister = endpointInformer.Lister()
		c.endpointSynced = endpointInformer.Informer().HasSynced
	}
	return c

}

func (c *Controller) enqueuePacketSampling(ps *crdv1alpha1.PacketSampling) {
	c.queue.Add(ps.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketSampling events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting packetsampling controller.", "name", controllerName)
	defer klog.InfoS("Shutting down packetsampling controller.", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetSamplingSynced}
	if c.enableAntreaProxy {
		cacheSynced = append(cacheSynced, c.serviceListerSynced, c.endpointSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	err := defaultFS.MkdirAll(packetDirectory, 0755)
	if err != nil {
		klog.ErrorS(err, "Couldn't create directory for storing sampling packets", "directory", packetDirectory)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addPacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling ADD event", "name", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) updatePacketSampling(_, obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling UPDATE EVENT", "name", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) deletePacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling DELETE event", "name", ps.Name)
	err := deletePcapngFile(string(ps.UID))
	if err != nil {
		klog.ErrorS(err, "Couldn't delete pcapng file")

	}
	c.enqueuePacketSampling(ps)

}

func deletePcapngFile(uid string) error {
	return defaultFS.Remove(uidToPath(uid))
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
		klog.ErrorS(nil, "Expected string in work queue but got:", "obj", obj)
		return true
	} else if err := c.syncPacketSampling(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing PacketSampling, exiting.", "key", key)
	}
	return true
}

func (c *Controller) validatePacketSampling(ps *crdv1alpha1.PacketSampling) error {
	if ps.Spec.Destination.Service != "" && !c.enableAntreaProxy {
		return errors.New("using Service destination requires AntreaProxy feature enabled")
	}
	if ps.Spec.Destination.IP != "" {
		destIP := net.ParseIP(ps.Spec.Destination.IP)
		if destIP == nil {
			return fmt.Errorf("destination IP %s is not valid", ps.Spec.Destination.IP)
		}
		if !c.enableAntreaProxy && c.serviceCIDR.Contains(destIP) {
			return errors.New("using ClusterIP destination requires AntreaProxy feature enabled")
		}
	}
	return nil
}

func (c *Controller) errorPacketSamplingCRD(ps *crdv1alpha1.PacketSampling, reason string) (*crdv1alpha1.PacketSampling, error) {
	ps.Status.Phase = crdv1alpha1.PacketSamplingFailed

	type PacketSampling struct {
		Status crdv1alpha1.PacketSamplingStatus `json:"status,omitempty"`
	}
	patchData := PacketSampling{
		Status: crdv1alpha1.PacketSamplingStatus{Phase: ps.Status.Phase, Reason: reason},
	}
	payloads, _ := json.Marshal(patchData)
	return c.crdClient.CrdV1alpha1().PacketSamplings().Patch(context.TODO(), ps.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")

}

func (c *Controller) cleanupPacketSampling(psName string) {
	psState := c.deletePacketSamplingState(psName)
	if psState != nil {
		err := c.ofClient.UninstallPacketSamplingFlows(uint8(psState.tag))
		if err != nil {
			klog.ErrorS(err, "Error cleaning up flows for PacketSampling.", "name", psName)
		}
		err = psState.pcapngWriter.Flush()
		if err != nil {
			klog.ErrorS(err, "Error flushing pcapng file for PacketSampling %s: %v", "name", psName, err)
		}
		err = psState.pcapngFile.Close()
		if err != nil {
			klog.ErrorS(err, "Error closing pcapng file for PacketSampling %s: %v", "name", psName)
		}
	}
}

func (c *Controller) deletePacketSamplingState(psName string) *packetSamplingState {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	for tag, state := range c.runningPacketSamplings {
		if state.name == psName {
			delete(c.runningPacketSamplings, tag)
			return state
		}
	}
	return nil
}

func (c *Controller) startPacketSampling(ps *crdv1alpha1.PacketSampling) error {
	err := c.validatePacketSampling(ps)
	defer func() {
		if err != nil {
			c.cleanupPacketSampling(ps.Name)
			c.errorPacketSamplingCRD(ps, fmt.Sprintf("Node: %s, error:%+v", c.nodeConfig.Name, err))

		}
	}()
	if err != nil {
		return err
	}

	receiverOnly := false
	senderOnly := true
	var pod, ns string
	if ps.Spec.Destination.Pod != "" {
		pod = ps.Spec.Source.Pod
		ns = ps.Spec.Source.Namespace
		senderOnly = false
		if ps.Spec.Source.Pod == "" {
			receiverOnly = true
		}
	} else {
		pod = ps.Spec.Source.Pod
		ns = ps.Spec.Source.Namespace
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	isSender := !receiverOnly && len(podInterfaces) > 0

	var packet, matchPacket *binding.Packet
	var endpointPackets []binding.Packet
	var ofPort uint32

	if len(podInterfaces) > 0 {
		packet, err = c.preparePacket(ps, podInterfaces[0], receiverOnly)
		if err != nil {
			return err
		}
		ofPort = uint32(podInterfaces[0].OFPort)
		matchPacket = packet
		klog.V(2).InfoS("PacketSampling packet:", "packet", *packet)
		if senderOnly && ps.Spec.Destination.Service != "" {
			endpointPackets, err = c.genEndpointMatchPackets(ps)
			if err != nil {
				return fmt.Errorf("couldn't generate endpoint match packets: %w", err)
			}
		}
	}

	c.runningPacketSamplingsMutex.Lock()
	psState := packetSamplingState{
		name: ps.Name, tag: ps.Status.DataplaneTag,
		receiverOnly: receiverOnly, isSender: isSender,
		maxNumCapturedPackets: ps.Spec.FirstNSamplingConfig.Number,
	}

	exists, err := fileExists(string(ps.UID))
	if err != nil {
		return fmt.Errorf("couldn't check if the file exists: %w", err)

	}
	if exists {
		return fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	}

	file, err := createPcapngFile(string(ps.UID))
	if err != nil {
		return fmt.Errorf("couldn't craete pcapng file: %w", err)
	}

	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("couldn't init pcap writer: %w", err)
	}

	psState.shouldSyncPackets = len(podInterfaces) > 0
	psState.uid = string(ps.UID)
	psState.pcapngFile = file
	psState.pcapngWriter = writer

	if psState.shouldSyncPackets {
		psState.updateRateLimiter = rate.NewLimiter(rate.Every(samplingStatusUpdatePeriod), 1)
	}
	c.runningPacketSamplings[psState.tag] = &psState
	c.runningPacketSamplingsMutex.Unlock()

	timeout := ps.Spec.Timeout
	if timeout == 0 {
		timeout = crdv1alpha1.DefaultPacketSamplingTimeout
	}
	if psState.shouldSyncPackets {
		klog.V(2).InfoS("installing flow entries for PacketSampling.", "name", ps.Name)
		err = c.ofClient.InstallPacketSamplingFlows(uint8(psState.tag), senderOnly, receiverOnly, matchPacket, endpointPackets, ofPort, timeout)
		if err != nil {
			klog.ErrorS(err, "install flow entries failed.", "name", ps.Name)
		}
	}
	return err

}

func createPcapngFile(uid string) (afero.File, error) {
	return defaultFS.Create(uidToPath(uid))
}

func fileExists(uid string) (bool, error) {
	_, err := defaultFS.Stat(uidToPath(uid))
	if err == nil {
		return true, nil
	} else {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}
}

// genEndpointMatchPackets generates match packets(with dest endpoint's ip/port info) besides the normal match packet.
// these match packets will help the pipeline to capture the pod -> svc traffic.
// TODO: 1. support name based port name 2. dual-stack support
func (c *Controller) genEndpointMatchPackets(ps *crdv1alpha1.PacketSampling) ([]binding.Packet, error) {
	if ps.Spec.Destination.Service != "" {
		var port int32
		if ps.Spec.Packet.TransportHeader.TCP != nil {
			port = ps.Spec.Packet.TransportHeader.TCP.DstPort
		} else if ps.Spec.Packet.TransportHeader.UDP != nil {
			port = ps.Spec.Packet.TransportHeader.UDP.DstPort
		}

		var packets []binding.Packet
		dstSvc, err := c.serviceLister.Services(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
		if err != nil {
			return nil, err
		}

		for _, item := range dstSvc.Spec.Ports {
			if item.Port == port {
				if item.TargetPort.Type == intstr.Int {
					port = item.TargetPort.IntVal
				}
			}
		}

		dstEndpoint, err := c.endpointLister.Endpoints(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
		if err != nil {
			return nil, err
		}
		for _, item := range dstEndpoint.Subsets[0].Addresses {
			packet := binding.Packet{}
			packet.DestinationIP = net.ParseIP(item.IP)
			if port != 0 {
				packet.DestinationPort = uint16(port)
			}
			packet.IPProto = parseTargetProto(&ps.Spec.Packet)
			packets = append(packets, packet)
		}
		return packets, nil
	}
	return nil, nil

}

func (c *Controller) preparePacket(ps *crdv1alpha1.PacketSampling, intf *interfacestore.InterfaceConfig, receiverOnly bool) (*binding.Packet, error) {
	packet := new(binding.Packet)
	packet.IsIPv6 = ps.Spec.Packet.IPv6Header != nil

	if receiverOnly {
		if ps.Spec.Source.IP != "" {
			packet.SourceIP = net.ParseIP(ps.Spec.Source.IP)
		}
		packet.DestinationMAC = intf.MAC
	} else if ps.Spec.Destination.IP != "" {
		packet.DestinationIP = net.ParseIP(ps.Spec.Destination.IP)
		if packet.DestinationIP == nil {
			return nil, errors.New("destination IP is not valid")
		}
	} else if ps.Spec.Destination.Pod != "" {
		dstPodInterfaces := c.interfaceStore.GetContainerInterfacesByPod(ps.Spec.Destination.Pod, ps.Spec.Destination.Namespace)
		if len(dstPodInterfaces) > 0 {
			if packet.IsIPv6 {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv6Addr()
			} else {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv4Addr()
			}
		} else {
			dstPod, err := c.kubeClient.CoreV1().Pods(ps.Spec.Destination.Namespace).Get(context.TODO(), ps.Spec.Destination.Pod, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get the destination pod %s/%s: %v", ps.Spec.Destination.Namespace, ps.Spec.Destination.Pod, err)
			}
			podIPs := make([]net.IP, len(dstPod.Status.PodIPs))
			for i, ip := range dstPod.Status.PodIPs {
				podIPs[i] = net.ParseIP(ip.IP)
			}
			if packet.IsIPv6 {
				packet.DestinationIP, _ = util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			} else {
				packet.DestinationIP = util.GetIPv4Addr(podIPs)
			}
		}
		if packet.DestinationIP == nil {
			if packet.IsIPv6 {
				return nil, errors.New("destination Pod does not have an IPv6 address")
			}
			return nil, errors.New("destination Pod does not have an IPv4 address")
		}
	} else if ps.Spec.Destination.Service != "" {
		dstSvc, err := c.serviceLister.Services(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
		if err != nil {
			return nil, fmt.Errorf("failed to get the destination service %s/%s: %v", ps.Spec.Destination.Namespace, ps.Spec.Destination.Service, err)
		}
		if dstSvc.Spec.ClusterIP == "" {
			return nil, errors.New("destination Service does not have an ClusterIP")
		}

		packet.DestinationIP = net.ParseIP(dstSvc.Spec.ClusterIP)
		if !packet.IsIPv6 {
			packet.DestinationIP = packet.DestinationIP.To4()
			if packet.DestinationIP == nil {
				return nil, errors.New("destination Service does not have an IPv4 address")
			}
		} else if packet.DestinationIP.To4() != nil {
			return nil, errors.New("destination Service does not have an IPv6 address")
		}
	} else {
		return nil, errors.New("destination is not specified")
	}

	if ps.Spec.Packet.TransportHeader.TCP != nil {
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.TCP.DstPort)
		if ps.Spec.Packet.TransportHeader.TCP.Flags != 0 {
			packet.TCPFlags = uint8(ps.Spec.Packet.TransportHeader.TCP.Flags)
		}
	} else if ps.Spec.Packet.TransportHeader.UDP != nil {
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.UDP.DstPort)
	}

	packet.IPProto = parseTargetProto(&ps.Spec.Packet)
	return packet, nil
}

func parseTargetProto(packet *crdv1alpha1.Packet) uint8 {
	var ipProto uint8
	var isIPv6 bool
	if packet.IPv6Header != nil {
		isIPv6 = true
		if packet.IPv6Header.NextHeader != nil {
			ipProto = uint8(*packet.IPv6Header.NextHeader)
		}
	} else if packet.IPHeader.Protocol != 0 {
		ipProto = uint8(packet.IPHeader.Protocol)
	}

	if packet.TransportHeader.TCP != nil {
		ipProto = protocol.Type_TCP
	} else if packet.TransportHeader.UDP != nil {
		ipProto = protocol.Type_UDP
	} else if packet.TransportHeader.ICMP != nil || ipProto == 0 {
		ipProto = protocol.Type_ICMP
		if isIPv6 {
			ipProto = protocol.Type_IPv6ICMP
		}
	}
	return ipProto
}

func (c *Controller) syncPacketSampling(psName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing PacketSampling.", "name", psName, "startTime", time.Since(startTime))
	}()

	ps, err := c.packetSamplingLister.Get(psName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPacketSampling(psName)
			return nil
		}
		return err
	}

	switch ps.Status.Phase {
	case crdv1alpha1.PacketSamplingRunning:
		if ps.Status.DataplaneTag != 0 {
			start := false
			c.runningPacketSamplingsMutex.Lock()
			if _, ok := c.runningPacketSamplings[ps.Status.DataplaneTag]; !ok {
				start = true
			}
			c.runningPacketSamplingsMutex.Unlock()
			if start {
				err = c.startPacketSampling(ps)
			}
		} else {
			klog.Warningf("Invalid data plane tag %s for packet. packetsampling: %s", ps.Status.DataplaneTag, ps.Name)
		}
	default:
		c.cleanupPacketSampling(psName)
	}
	return err

}

func (c *Controller) getUploaderByProtocol(protocol StorageProtocolType) (ftp.UpLoader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) uploadPackets(ps *crdv1alpha1.PacketSampling, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketSampling", "name", ps.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload support bundle while getting uploader: %v", err)
	}
	serverAuth, err := ftp.ParseBundleAuth(ps.Spec.Authentication, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication defined in the PacketSampling CR", "name", ps.Name, "authentication", ps.Spec.Authentication)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	fileName := c.nodeConfig.Name + "_" + string(ps.UID) + ".pcapng"

	return uploader.Upload(ps.Spec.FileServer.URL, fileName, cfg, outputFile)

}
