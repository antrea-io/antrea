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

package packetcapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/packetcap/go-pcap"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	klog "k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
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
	controllerName               = "AntreaAgentPacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4

	// reason for timeout
	captureTimeoutReason   = "PacketCapture timeout"
	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketCaptureTimeout)

	captureStatusUpdatePeriod = 10 * time.Second

	// PacketCapture uses a dedicated secret object to store auth info for file server.
	// #nosec G101
	fileServerAuthSecretName      = "antrea-packetcapture-fileserver-auth"
	fileServerAuthSecretNamespace = "kube-system"

	// max packet size for pcap capture.
	snapshotLen = 65536
)

var (
	packetDirectory = getPacketDirectory()
	defaultFS       = afero.NewOsFs()
)

// go-pcap seems doesn't support filter with numeric protocol number yet. use this map
// to translate to string.
var protocolMap = map[int]string{
	1:   "icmp",
	6:   "tcp",
	17:  "udp",
	58:  "icmp6",
	132: "sctp",
}

func getPacketDirectory() string {
	return filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
}

type packetCaptureState struct {
	// name is the PacketCapture name
	name string
	// numCapturedPackets record how many packets have been captured. Due to the RateLimiter,
	// this maybe not be realtime data.
	numCapturedPackets int32
	// maxNumCapturedPackets is target number limit for our capture. If numCapturedPackets=maxNumCapturedPackets, means
	// the PacketCapture is finished successfully.
	maxNumCapturedPackets int32
	// updateRateLimiter controls the frequency of the updates to PacketCapture status.
	updateRateLimiter *rate.Limiter
	// pcapngFile is the file object for the packet file.
	pcapngFile afero.File
	// pcapngWriter is the writer for the packet file.
	pcapngWriter *pcapgo.NgWriter
}

type Controller struct {
	kubeClient            clientset.Interface
	crdClient             clientsetversioned.Interface
	packetCaptureInformer crdinformers.PacketCaptureInformer
	packetCaptureLister   crdlisters.PacketCaptureLister
	packetCaptureSynced   cache.InformerSynced
	interfaceStore        interfacestore.InterfaceStore
	nodeConfig            *config.NodeConfig
	queue                 workqueue.TypedRateLimitingInterface[string]
	sftpUploader          ftp.Uploader
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
) *Controller {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		interfaceStore:        interfaceStore,
		nodeConfig:            nodeConfig,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
		),
		sftpUploader: &ftp.SftpUploader{},
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	return c
}

func (c *Controller) enqueuePacketCapture(pc *crdv1alpha1.PacketCapture) {
	c.queue.Add(pc.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketCapture events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting packetcapture controller", "name", controllerName)
	defer klog.InfoS("Shutting down packetcapture controller", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetCaptureSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	err := defaultFS.MkdirAll(packetDirectory, 0755)
	if err != nil {
		klog.ErrorS(err, "Couldn't create directory for storing captured packets", "directory", packetDirectory)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addPacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture ADD event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) updatePacketCapture(_, obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture UPDATE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) deletePacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture DELETE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func nameToPath(name string) string {
	return filepath.Join(packetDirectory, name+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketCaptureItem() {
	}
}

func (c *Controller) processPacketCaptureItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	if err := c.syncPacketCapture(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing PacketCapture, exiting", "key", key)
	}
	return true
}

func (c *Controller) cleanupPacketCapture(pcName string) {
	path := nameToPath(pcName)
	exist, err := afero.Exists(defaultFS, path)
	if err != nil {
		klog.ErrorS(err, "Failed to check if path exists", "path", path)
	}
	if !exist {
		return
	}
	if err := defaultFS.Remove(path); err == nil {
		klog.V(2).InfoS("Deleted pcap file", "name", pcName, "path", path)
	} else {
		klog.ErrorS(err, "Failed to delete pcap file", "name", pcName, "path", path)
	}
}

func getPacketFileAndWriter(name string) (afero.File, *pcapgo.NgWriter, error) {
	filePath := nameToPath(name)
	var file afero.File
	if _, err := os.Stat(filePath); err == nil {
		return nil, nil, fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	} else if os.IsNotExist(err) {
		file, err = defaultFS.Create(filePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create pcapng file: %w", err)
		}
	} else {
		return nil, nil, fmt.Errorf("couldn't check if the file exists: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't initialize pcap writer: %w", err)
	}
	return file, writer, nil
}

func (c *Controller) startPacketCapture(pc *crdv1alpha1.PacketCapture) error {
	var err error
	defer func() {
		if err != nil {
			c.cleanupPacketCapture(pc.Name)
			err := c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, fmt.Sprintf("Node: %s, Error: %+v", c.nodeConfig.Name, err), 0)
			if err != nil {
				klog.ErrorS(err, "failed to update PacketCapture status")
			}
		}
	}()

	var pod, ns string
	if pc.Spec.Source.Pod != nil {
		pod = pc.Spec.Source.Pod.Name
		ns = pc.Spec.Source.Pod.Namespace
	} else {
		pod = pc.Spec.Destination.Pod.Name
		ns = pc.Spec.Destination.Pod.Namespace
	}
	pcState := &packetCaptureState{name: pc.Name}
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	if len(podInterfaces) == 0 {
		return nil
	}
	device := podInterfaces[0].InterfaceName
	var matchPacket *binding.Packet
	matchPacket, err = c.createMatchPacket(pc)
	if err != nil {
		return err
	}
	klog.V(2).InfoS("PacketCapture trying to match packet", "name", pc.Name, "packet", *matchPacket)
	pcState.maxNumCapturedPackets = pc.Spec.CaptureConfig.FirstN.Number
	file, writer, err := getPacketFileAndWriter(pc.Name)
	if err != nil {
		return err
	}
	pcState.pcapngFile = file
	pcState.pcapngWriter = writer
	pcState.updateRateLimiter = rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1)
	timeout := crdv1alpha1.DefaultPacketCaptureTimeout
	if pc.Spec.Timeout != nil {
		timeout = *pc.Spec.Timeout
	}
	exp := genBPFFilterStr(matchPacket, pc.Spec.Packet)
	klog.V(2).InfoS("Starting capture on device", "name", pc.Name, "device", device, "filter", exp)
	err = c.performCapture(pcState, device, exp, time.Duration(timeout)*time.Second)
	return err
}

// genBPFFilterStr generate BPF filter string based on the origin PacketCapture spec and
// parsed ip / port info (matchPacket) from it. An example generated filter string would be like:
// 'src 192.168.0.1 and dst 192.168.0.2 and src port 8080 and dst port 8081 and tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
func genBPFFilterStr(matchPacket *binding.Packet, packetSpec *crdv1alpha1.Packet) string {
	exp := ""
	protocol := packetSpec.Protocol
	if protocol != nil {
		if protocol.Type == intstr.Int {
			if val, ok := protocolMap[protocol.IntValue()]; ok {
				exp += val
			} else {
				// go-pcap didn't support proto number for now.
				exp += "proto " + strconv.Itoa(protocol.IntValue())
			}
		} else {
			exp += strings.ToLower(protocol.String())
		}
	}
	if exp != "" {
		if exp == "icmp" || exp == "icmp6" {
			// go-pcap bug, see:https://github.com/packetcap/go-pcap/issues/59
			// cannot use `and` now
			exp += " "
		} else {
			exp += " and "
		}

	}
	if matchPacket.SourceIP != nil {
		exp += "src host " + matchPacket.SourceIP.String()
	}
	if matchPacket.DestinationIP != nil {
		exp += " and dst host " + matchPacket.DestinationIP.String()
	}
	if matchPacket.SourcePort > 0 {
		exp += " and src port " + strconv.Itoa(int(matchPacket.SourcePort))
	}
	if matchPacket.DestinationPort > 0 {
		exp += " and dst port " + strconv.Itoa(int(matchPacket.DestinationPort))
	}

	tcp := packetSpec.TransportHeader.TCP
	if tcp != nil {
		if tcp.Flags != nil {
			exp += " and " + *tcp.Flags
		}
	}
	return exp
}

func (c *Controller) performCapture(captureState *packetCaptureState, device string, filter string, timeout time.Duration) error {
	handle, err := pcap.OpenLive(device, snapshotLen, true, timeout, false)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		return err
	}

	timer := time.NewTicker(timeout)
	defer timer.Stop()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
	packetSource.NoCopy = true
	for {
		select {
		case packet := <-packetSource.Packets():
			if captureState.numCapturedPackets == captureState.maxNumCapturedPackets {
				break
			}
			captureState.numCapturedPackets++
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(packet.Data()),
				Length:        len(packet.Data()),
			}
			err = captureState.pcapngWriter.WritePacket(ci, packet.Data())
			if err != nil {
				return fmt.Errorf("couldn't write packet: %w", err)
			}
			klog.V(9).InfoS("capture packet", "name", captureState.name, "count",
				captureState.numCapturedPackets, "len", ci.Length)

			reachTarget := captureState.numCapturedPackets == captureState.maxNumCapturedPackets
			// use rate limiter to reduce the times we need to update status.
			if reachTarget || captureState.updateRateLimiter.Allow() {
				pc, err := c.packetCaptureLister.Get(captureState.name)
				if err != nil {
					return fmt.Errorf("get PacketCapture failed: %w", err)
				}
				// if reach the target. flush the file and upload it.
				if reachTarget {
					if err := captureState.pcapngWriter.Flush(); err != nil {
						return err
					}
					if err := c.uploadPackets(pc, captureState.pcapngFile); err != nil {
						return err
					}
					if err := captureState.pcapngFile.Close(); err != nil {
						return err
					}
					if err := c.setPacketsFilePathStatus(pc.Name); err != nil {
						return err
					}
				}

				err = c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureRunning, "", captureState.numCapturedPackets)
				if err != nil {
					return fmt.Errorf("failed to update the PacketCapture: %w", err)
				}
				klog.InfoS("Updated PacketCapture", "PacketCapture", klog.KObj(pc), "numCapturedPackets", captureState.numCapturedPackets)
			}
		case <-timer.C:
			pc, err := c.packetCaptureLister.Get(captureState.name)
			if err != nil {
				return fmt.Errorf("get PacketCapture failed: %w", err)
			}
			klog.InfoS("PacketCapture timeout", "name", pc.Name)
			return c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, captureTimeoutReason, 0)
		}
	}
}

func (c *Controller) getPodIP(podRef *crdv1alpha1.PodReference, isIPv6 bool) (net.IP, error) {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	var result net.IP
	if len(podInterfaces) > 0 {
		if isIPv6 {
			result = podInterfaces[0].GetIPv6Addr()
		} else {
			result = podInterfaces[0].GetIPv4Addr()
		}
	} else {
		pod, err := c.kubeClient.CoreV1().Pods(podRef.Namespace).Get(context.TODO(), podRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get Pod %s/%s: %v", podRef.Namespace, podRef.Name, err)
		}
		podIPs := make([]net.IP, len(pod.Status.PodIPs))
		for i, ip := range pod.Status.PodIPs {
			podIPs[i] = net.ParseIP(ip.IP)
		}
		if isIPv6 {
			ip, err := util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			if err != nil {
				return nil, err
			} else {
				result = ip
			}
		} else {
			result = util.GetIPv4Addr(podIPs)
		}
	}
	if result == nil {
		family := "IPv4"
		if isIPv6 {
			family = "IPv6"
		}
		return nil, fmt.Errorf("cannot find IP with %s AddressFamily for Pod %s/%s", family, podRef.Namespace, podRef.Name)
	}
	return result, nil
}

func (c *Controller) createMatchPacket(pc *crdv1alpha1.PacketCapture) (*binding.Packet, error) {
	packet := new(binding.Packet)
	if pc.Spec.Packet == nil {
		pc.Spec.Packet = &crdv1alpha1.Packet{
			IPFamily: v1.IPv4Protocol,
		}
	}

	packet.IsIPv6 = pc.Spec.Packet.IPFamily == v1.IPv6Protocol
	if pc.Spec.Source.Pod != nil {
		ip, err := c.getPodIP(pc.Spec.Source.Pod, packet.IsIPv6)
		if err != nil {
			return nil, err
		} else {
			packet.SourceIP = ip
		}
	} else if pc.Spec.Source.IP != nil {
		packet.SourceIP = net.ParseIP(*pc.Spec.Source.IP)
		if packet.SourceIP == nil {
			return nil, errors.New("invalid ip address: " + *pc.Spec.Source.IP)
		}
	}

	if pc.Spec.Destination.Pod != nil {
		ip, err := c.getPodIP(pc.Spec.Destination.Pod, packet.IsIPv6)
		if err != nil {
			return nil, err
		} else {
			packet.DestinationIP = ip
		}
	} else if pc.Spec.Destination.IP != nil {
		packet.DestinationIP = net.ParseIP(*pc.Spec.Destination.IP)
		if packet.DestinationIP == nil {
			return nil, errors.New("invalid ip address: " + *pc.Spec.Destination.IP)
		}
	}

	if pc.Spec.Packet.TransportHeader.TCP != nil {
		if pc.Spec.Packet.TransportHeader.TCP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.TCP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.TCP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.TCP.DstPort)
		}
	} else if pc.Spec.Packet.TransportHeader.UDP != nil {
		if pc.Spec.Packet.TransportHeader.UDP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.UDP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.UDP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.UDP.DstPort)
		}
	}
	return packet, nil
}

func (c *Controller) syncPacketCapture(pcName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing PacketCapture", "name", pcName, "startTime", time.Since(startTime))
	}()

	pc, err := c.packetCaptureLister.Get(pcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPacketCapture(pcName)
			return nil
		}
		return err
	}

	switch pc.Status.Phase {
	case "":
		err = c.initPacketCapture(pc)
	case crdv1alpha1.PacketCaptureRunning:
		err = c.checkPacketCaptureStatus(pc)
	case crdv1alpha1.PacketCaptureFailed:
		c.cleanupPacketCapture(pcName)
	}
	return err

}

func (c *Controller) getUploaderByProtocol(protocol StorageProtocolType) (ftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func getDefaultFileServerAuth() *crdv1alpha1.BundleServerAuthConfiguration {
	return &crdv1alpha1.BundleServerAuthConfiguration{
		AuthType: crdv1alpha1.BasicAuthentication,
		AuthSecret: &v1.SecretReference{
			Name:      fileServerAuthSecretName,
			Namespace: fileServerAuthSecretNamespace,
		},
	}
}

func (c *Controller) uploadPackets(pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
	if pc.Spec.FileServer == nil {
		klog.V(2).Info("No fileserver info found in PacketCapture, skip upload packets file")
		return nil
	}
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload support bundle while getting uploader: %v", err)
	}
	authConfig := getDefaultFileServerAuth()
	serverAuth, err := ftp.ParseBundleAuth(*authConfig, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication for the fileServer", "name", pc.Name, "authentication", authConfig)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(pc.Name), cfg, outputFile)
}

// initPacketCapture mark the PacketCapture as running
func (c *Controller) initPacketCapture(pc *crdv1alpha1.PacketCapture) error {
	err := c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureRunning, "", 0)
	if err != nil {
		return err
	}
	return c.startPacketCapture(pc)
}

func (c *Controller) updatePacketCaptureStatus(pc *crdv1alpha1.PacketCapture, phase crdv1alpha1.PacketCapturePhase, reason string, numCapturedPackets int32) error {
	latestPC, err := c.packetCaptureLister.Get(pc.Name)
	if err != nil {
		return fmt.Errorf("get PacketCapture failed: %w", err)
	}
	type PacketCapture struct {
		Status crdv1alpha1.PacketCaptureStatus `json:"status,omitempty"`
	}
	patchData := PacketCapture{Status: crdv1alpha1.PacketCaptureStatus{Phase: phase, PacketsFilePath: latestPC.Status.PacketsFilePath}}
	if phase == crdv1alpha1.PacketCaptureRunning && pc.Status.StartTime == nil {
		t := metav1.Now()
		patchData.Status.StartTime = &t
	}
	if phase == crdv1alpha1.PacketCaptureFailed {
		patchData.Status.PacketsFilePath = ""
	}
	if reason != "" {
		patchData.Status.Reason = reason
	}
	if numCapturedPackets != 0 {
		patchData.Status.NumCapturedPackets = numCapturedPackets
	}
	payloads, _ := json.Marshal(patchData)
	_, err = c.crdClient.CrdV1alpha1().PacketCaptures().Patch(context.TODO(), pc.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
	return err
}

// we also support only store the packets file in the antrea-agent Pod, so add the file path including the Pod name here for users to
// know where the file is located at.
func (c *Controller) setPacketsFilePathStatus(name string) error {
	type PacketCapture struct {
		Status crdv1alpha1.PacketCaptureStatus `json:"status,omitempty"`
	}
	patchData := PacketCapture{
		Status: crdv1alpha1.PacketCaptureStatus{
			PacketsFilePath: os.Getenv("POD_NAME") + ":" + nameToPath(name),
		},
	}
	payloads, _ := json.Marshal(patchData)
	_, err := c.crdClient.CrdV1alpha1().PacketCaptures().Patch(context.TODO(), name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
	return err
}

// checkPacketCaptureStatus is only called for PacketCaptures in the Running phase
func (c *Controller) checkPacketCaptureStatus(pc *crdv1alpha1.PacketCapture) error {
	if checkPacketCaptureSucceeded(pc) {
		klog.V(4).InfoS("PacketCapture succeeded", "name", pc.Name)
		return c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureSucceeded, "", 0)
	}

	if isPacketCaptureTimeout(pc) {
		return c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, captureTimeoutReason, 0)
	}
	return nil
}

func checkPacketCaptureSucceeded(pc *crdv1alpha1.PacketCapture) bool {
	succeeded := false
	cfg := pc.Spec.CaptureConfig.FirstN
	captured := pc.Status.NumCapturedPackets
	if cfg != nil && captured == cfg.Number {
		succeeded = true
	}
	return succeeded
}

func isPacketCaptureTimeout(pc *crdv1alpha1.PacketCapture) bool {
	var timeout time.Duration
	if pc.Spec.Timeout != nil {
		timeout = time.Duration(*pc.Spec.Timeout) * time.Second
	} else {
		timeout = defaultTimeoutDuration
	}
	var startTime time.Time
	if pc.Status.StartTime != nil {
		startTime = pc.Status.StartTime.Time
	} else {
		klog.V(2).InfoS("StartTime field in PacketCapture Status should not be empty", "PacketCapture", klog.KObj(pc))
		startTime = pc.CreationTimestamp.Time
	}
	return startTime.Add(timeout).Before(time.Now())
}
