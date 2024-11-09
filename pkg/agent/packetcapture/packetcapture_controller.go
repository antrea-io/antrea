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
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/packetcapture/capture"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/auth"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/sftp"
)

type storageProtocolType string

const (
	sftpProtocol storageProtocolType = "sftp"
)

const (
	controllerName               = "PacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 60 * time.Second

	defaultWorkers = 4

	// defines how many capture request we can handle concurrently. waiting captures will be
	// marked as Pending until they can be processed.
	maxConcurrentCaptures     = 16
	captureStatusUpdatePeriod = 10 * time.Second
	// PacketCapture uses a dedicated Secret object to store authentication information for a file server.
	// #nosec G101
	fileServerAuthSecretName = "antrea-packetcapture-fileserver-auth"
)

type packetCapturePhase string

const (
	packetCapturePhasePending  packetCapturePhase = ""
	packetCapturePhaseStarted  packetCapturePhase = "Started"
	packetCapturePhaseComplete packetCapturePhase = "Complete"
)

var (
	packetDirectory = filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
	defaultFS       = afero.NewOsFs()
)

type packetCaptureState struct {
	// capturedPacketsNum records how many packets have been captured. Due to the RateLimiter,
	// this may not be the real-time data.
	capturedPacketsNum int32
	// targetCapturedPacketsNum is the target number limit for a PacketCapture. When numCapturedPackets == targetCapturedPacketsNum, it means
	// the PacketCapture is done successfully.
	targetCapturedPacketsNum int32
	// phase is the phase of the PacketCapture.
	phase packetCapturePhase
	// filePath is the final path shown in PacketCapture's status.
	filePath string
	// err is the latest error observed in the capture.
	err error
	// cancel is the cancel function for capture context.
	cancel context.CancelFunc
}

func (pcs *packetCaptureState) isCaptureSuccessful() bool {
	return pcs.capturedPacketsNum == pcs.targetCapturedPacketsNum && pcs.targetCapturedPacketsNum > 0
}

type Controller struct {
	kubeClient            clientset.Interface
	crdClient             clientsetversioned.Interface
	packetCaptureInformer crdinformers.PacketCaptureInformer
	packetCaptureLister   crdlisters.PacketCaptureLister
	packetCaptureSynced   cache.InformerSynced
	interfaceStore        interfacestore.InterfaceStore
	queue                 workqueue.TypedRateLimitingInterface[string]
	sftpUploader          sftp.Uploader
	captureInterface      PacketCapturer
	mutex                 sync.Mutex
	// A name-state mapping for all PacketCapture CRs.
	captures           map[string]*packetCaptureState
	numRunningCaptures int
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
) (*Controller, error) {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		interfaceStore:        interfaceStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
		),
		sftpUploader: sftp.NewUploader(),
		captures:     make(map[string]*packetCaptureState),
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	capture, err := capture.NewPcapCapture()
	if err != nil {
		return nil, err
	}
	c.captureInterface = capture
	return c, nil
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
		klog.ErrorS(err, "Couldn't create the directory for storing captured packets", "directory", packetDirectory)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addPacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.V(2).InfoS("Processing PacketCapture ADD event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) updatePacketCapture(oldObj, newObj interface{}) {
	newPc := newObj.(*crdv1alpha1.PacketCapture)
	oldPc := oldObj.(*crdv1alpha1.PacketCapture)
	if newPc.Generation != oldPc.Generation {
		klog.V(2).InfoS("Processing PacketCapture UPDATE event", "name", newPc.Name)
		c.enqueuePacketCapture(newPc)
	}
}

func (c *Controller) deletePacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.V(2).InfoS("Processing PacketCapture DELETE event", "name", pc.Name)
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
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing PacketCapture, requeueing", "key", key)
	}
	return true
}

func (c *Controller) syncPacketCapture(pcName string) error {
	cleanupStatus := func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		state := c.captures[pcName]
		if state != nil {
			if state.cancel != nil {
				state.cancel()
			}
			delete(c.captures, pcName)
		}
	}

	pc, err := c.packetCaptureLister.Get(pcName)
	if apierrors.IsNotFound(err) {
		c.cleanupPacketCapture(pcName)
		cleanupStatus()
		return nil
	}

	// Capture will not occur on this Node if a corresponding Pod interface is not found.
	device := c.getTargetCaptureDevice(pc)
	if device == "" {
		klog.V(4).InfoS("Skipping process PacketCapture", "name", pcName)
		return nil
	}

	if err := c.validatePacketCapture(&pc.Spec); err != nil {
		klog.ErrorS(err, "Invalid PacketCapture", "name", pc.Name)
		if updateErr := c.updateStatus(context.Background(), pcName, packetCaptureState{err: err}); updateErr != nil {
			klog.ErrorS(err, "Failed to update PacketCapture status", "name", pc.Name)
		}
		cleanupStatus()
		return nil
	}

	state := func() packetCaptureState {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		state := c.captures[pcName]
		if state == nil {
			state = &packetCaptureState{targetCapturedPacketsNum: pc.Spec.CaptureConfig.FirstN.Number}
			c.captures[pcName] = state
		}
		phase := state.phase
		klog.InfoS("Syncing PacketCapture", "name", pcName, "phase", phase)
		if phase != packetCapturePhasePending {
			return *state
		}

		if c.numRunningCaptures >= maxConcurrentCaptures {
			err = fmt.Errorf("PacketCapture running count reach limit")
		} else {
			// crd spec make sure it's not nil
			timeout := time.Duration(*pc.Spec.Timeout) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			state.cancel = cancel
			if err = c.startPacketCapture(ctx, pc, state, device); err != nil {
				phase = packetCapturePhaseComplete
			} else {
				phase = packetCapturePhaseStarted
				c.numRunningCaptures += 1
			}
		}
		state.phase = phase
		state.err = err
		c.captures[pcName] = state
		return *state
	}()

	if updateErr := c.updateStatus(context.Background(), pcName, state); updateErr != nil {
		return fmt.Errorf("error when patching status: %w", updateErr)
	}
	return err
}

func (c *Controller) validatePacketCapture(spec *crdv1alpha1.PacketCaptureSpec) error {
	if spec.Packet != nil {
		protocol := spec.Packet.Protocol
		if protocol != nil {
			if protocol.Type == intstr.String {
				if _, ok := capture.ProtocolMap[strings.ToUpper(protocol.StrVal)]; !ok {
					return fmt.Errorf("invalid protocol string, supported values are: %v (case insensitive)", slices.Collect(maps.Keys(capture.ProtocolMap)))
				}
			}
		}
	}
	return nil
}

func (c *Controller) cleanupPacketCapture(pcName string) {
	path := nameToPath(pcName)
	if err := defaultFS.RemoveAll(path); err == nil {
		klog.V(2).InfoS("Deleted the captured pcap file successfully", "name", pcName, "path", path)
	} else {
		klog.ErrorS(err, "Failed to delete the captured pcap file", "name", pcName, "path", path)
	}
}

func getPacketFileAndWriter(name string) (afero.File, *pcapgo.NgWriter, error) {
	filePath := nameToPath(name)
	var file afero.File
	if _, err := os.Stat(filePath); err == nil {
		klog.InfoS("Packet file already exists. This may be caused by an unexpected termination, will delete it", "path", filePath)
		if err := defaultFS.Remove(filePath); err != nil {
			return nil, nil, err
		}
	}
	file, err := defaultFS.Create(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pcapng file: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't initialize a pcap writer: %w", err)
	}
	return file, writer, nil
}

// getTargetCaptureDevice is trying to locate the target device for packet capture. If the target
// Pod does not exist on the current Node, the agent on this Node will not perform the capture.
// In the PacketCapture spec, at least one of `.Spec.Source.Pod` or `.Spec.Destination.Pod`
// should be set.
func (c *Controller) getTargetCaptureDevice(pc *crdv1alpha1.PacketCapture) string {
	var pod, ns string
	if pc.Spec.Source.Pod != nil {
		pod = pc.Spec.Source.Pod.Name
		ns = pc.Spec.Source.Pod.Namespace
	} else {
		pod = pc.Spec.Destination.Pod.Name
		ns = pc.Spec.Destination.Pod.Namespace
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	if len(podInterfaces) == 0 {
		return ""
	}
	return podInterfaces[0].InterfaceName
}

// startPacketCapture starts the capture on the target device. The actual capture process will be started
// in a separated go routine.
func (c *Controller) startPacketCapture(ctx context.Context, pc *crdv1alpha1.PacketCapture, pcState *packetCaptureState, device string) error {
	klog.V(2).InfoS("Started processing PacketCapture on the current Node", "name", pc.Name, "device", device)
	go func() {
		captureErr := c.performCapture(ctx, pc, pcState, device)
		func() {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			c.numRunningCaptures -= 1
			state := c.captures[pc.Name]
			if state != nil {
				state.phase = packetCapturePhaseComplete
				state.err = captureErr
			}

		}()
		c.enqueuePacketCapture(pc)
	}()
	return nil
}

func (c *Controller) performCapture(
	ctx context.Context,
	pc *crdv1alpha1.PacketCapture,
	captureState *packetCaptureState,
	device string,
) error {
	srcIP, dstIP, err := c.parseIPs(ctx, pc)
	if err != nil {
		return err
	}
	pcapngFile, pcapngWriter, err := getPacketFileAndWriter(pc.Name)
	if err != nil {
		return err
	}
	updateRateLimiter := rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1)
	packets, err := c.captureInterface.Capture(ctx, device, srcIP, dstIP, pc.Spec.Packet)
	if err != nil {
		klog.ErrorS(err, "Failed to start capture")
		return err
	}
	klog.InfoS("Starting packet capture", "name", pc.Name, "device", device)
	for {
		select {
		case packet := <-packets:
			c.mutex.Lock()
			captureState.capturedPacketsNum++
			reachTarget := captureState.isCaptureSuccessful()
			klog.V(5).InfoS("Captured packets count", "name", pc.Name, "count", captureState.capturedPacketsNum)
			c.mutex.Unlock()
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(packet.Data()),
				Length:        len(packet.Data()),
			}
			err = pcapngWriter.WritePacket(ci, packet.Data())
			if err != nil {
				return fmt.Errorf("couldn't write packets: %w", err)
			}
			klog.V(5).InfoS("Captured packet length", "name", pc.Name, "len", ci.Length)

			// if reach the target. flush the file and upload it.
			if reachTarget {
				path := env.GetPodName() + ":" + nameToPath(pc.Name)
				statusPath := path
				if err = pcapngWriter.Flush(); err != nil {
					return err
				}
				if pc.Spec.FileServer != nil {
					err = c.uploadPackets(ctx, pc, pcapngFile)
					klog.V(4).InfoS("Upload captured packets", "name", pc.Name, "path", path)
					statusPath = fmt.Sprintf("%s/%s.pcapng", pc.Spec.FileServer.URL, pc.Name)
				}
				c.mutex.Lock()
				captureState.filePath = statusPath
				c.mutex.Unlock()
				if err != nil {
					return err
				}
				if err := pcapngFile.Close(); err != nil {
					klog.ErrorS(err, "Close pcapng file error", "name", pc.Name, "path", path)
				}
				return nil
			} else if updateRateLimiter.Allow() {
				// use rate limiter to reduce the times we need to update status.
				c.enqueuePacketCapture(pc)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Controller) getPodIP(ctx context.Context, podRef *crdv1alpha1.PodReference) (net.IP, error) {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	var podIP net.IP
	if len(podInterfaces) > 0 {
		podIP = podInterfaces[0].GetIPv4Addr()
	} else {
		pod, err := c.kubeClient.CoreV1().Pods(podRef.Namespace).Get(ctx, podRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get Pod %s/%s: %w", podRef.Namespace, podRef.Name, err)
		}
		podIPs := make([]net.IP, len(pod.Status.PodIPs))
		for i, ip := range pod.Status.PodIPs {
			podIPs[i] = net.ParseIP(ip.IP)
		}
		podIP = util.GetIPv4Addr(podIPs)
	}
	if podIP == nil {
		return nil, fmt.Errorf("cannot find IP with IPv4 address family for Pod %s/%s", podRef.Namespace, podRef.Name)
	}
	return podIP, nil
}

func (c *Controller) parseIPs(ctx context.Context, pc *crdv1alpha1.PacketCapture) (srcIP, dstIP net.IP, err error) {
	if pc.Spec.Source.Pod != nil {
		srcIP, err = c.getPodIP(ctx, pc.Spec.Source.Pod)
		if err != nil {
			return
		}
	} else if pc.Spec.Source.IP != nil {
		srcIP = net.ParseIP(*pc.Spec.Source.IP)
		if srcIP == nil {
			err = fmt.Errorf("invalid source IP address: %s", *pc.Spec.Source.IP)
			return
		}
	}
	if pc.Spec.Destination.Pod != nil {
		dstIP, err = c.getPodIP(ctx, pc.Spec.Destination.Pod)
		if err != nil {
			return
		}
	} else if pc.Spec.Destination.IP != nil {
		dstIP = net.ParseIP(*pc.Spec.Destination.IP)
		if dstIP == nil {
			err = fmt.Errorf("invalid destination IP address: %s", *pc.Spec.Destination.IP)
		}
	}
	return
}

func (c *Controller) getUploaderByProtocol(protocol storageProtocolType) (sftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func (c *Controller) uploadPackets(ctx context.Context, pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload packets while getting uploader: %w", err)
	}
	if _, err := outputFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to upload to the file server while setting offset: %v", err)
	}
	authSecret := v1.SecretReference{
		Name:      fileServerAuthSecretName,
		Namespace: env.GetAntreaNamespace(),
	}
	serverAuth, err := auth.GetAuthConfigurationFromSecret(ctx, auth.BasicAuthenticationType, &authSecret, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication for the file server", "name", pc.Name, "authSecret", authSecret)
		return err
	}
	if serverAuth.BasicAuthentication == nil {
		return fmt.Errorf("failed to get basic authentication info for the file server")
	}
	cfg := &ssh.ClientConfig{
		User: serverAuth.BasicAuthentication.Username,
		Auth: []ssh.AuthMethod{ssh.Password(serverAuth.BasicAuthentication.Password)},
		// #nosec G106: skip host key check here and users can specify their own checks if needed
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(pc.Name), cfg, outputFile)
}

func (c *Controller) updateStatus(ctx context.Context, name string, state packetCaptureState) error {
	toUpdate, getErr := c.packetCaptureLister.Get(name)
	if getErr != nil {
		klog.InfoS("Didn't find the original PacketCapture, skip updating status", "name", name)
		return nil
	}
	conditions := []crdv1alpha1.PacketCaptureCondition{}
	t := metav1.Now()
	updatedStatus := crdv1alpha1.PacketCaptureStatus{
		NumberCaptured: state.capturedPacketsNum,
		FilePath:       state.filePath,
	}

	if state.err != nil {
		updatedStatus.FilePath = ""
		if errors.Is(state.err, context.DeadlineExceeded) {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureComplete,
				Status:             metav1.ConditionStatus(v1.ConditionTrue),
				LastTransitionTime: t,
				Reason:             "Timeout",
			})

		} else if state.isCaptureSuccessful() {
			// most likely failed to upload after capture succeed.
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureComplete,
				Status:             metav1.ConditionStatus(v1.ConditionTrue),
				LastTransitionTime: t,
				Reason:             "Succeed",
			})
		} else {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureComplete,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: metav1.Now(),
				Reason:             "CaptureFailed",
				Message:            state.err.Error(),
			})
		}
		if toUpdate.Spec.FileServer != nil && state.filePath != "" {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureFileUploaded,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: t,
				Reason:             "UploadFailed",
				Message:            state.err.Error(),
			})
		}
		if state.phase == packetCapturePhasePending {
			conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureStarted,
					Status:             metav1.ConditionStatus(v1.ConditionFalse),
					LastTransitionTime: t,
					Reason:             "StartFailed",
					Message:            state.err.Error(),
				},
			}
		}
	} else {
		if state.isCaptureSuccessful() {
			conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureComplete,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				},
			}
			if toUpdate.Spec.FileServer != nil {
				conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				})
			}
		} else if state.phase == packetCapturePhaseStarted {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureStarted,
				Status:             metav1.ConditionStatus(v1.ConditionTrue),
				LastTransitionTime: t,
			})
		} else if state.phase == packetCapturePhasePending {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureStarted,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: t,
			})
		}

	}
	updatedStatus.Conditions = conditions

	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if toUpdate.Status.FilePath != "" {
			updatedStatus.FilePath = toUpdate.Status.FilePath
		}
		if updatedStatus.NumberCaptured == 0 && toUpdate.Status.NumberCaptured > 0 {
			updatedStatus.NumberCaptured = toUpdate.Status.NumberCaptured
		}

		updatedStatus.Conditions = mergeConditions(toUpdate.Status.Conditions, updatedStatus.Conditions)
		if packetCaptureStatusEqual(toUpdate.Status, updatedStatus) {
			return nil
		}
		toUpdate.Status = updatedStatus
		klog.V(2).InfoS("Updating PacketCapture", "name", name, "status", toUpdate.Status)
		_, updateErr := c.crdClient.CrdV1alpha1().PacketCaptures().UpdateStatus(ctx, toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && apierrors.IsConflict(updateErr) {
			var getErr error
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		// Return the error from UPDATE.
		return updateErr
	}); retryErr != nil {
		return retryErr
	}
	klog.V(2).InfoS("Updated PacketCapture", "name", name)
	return nil
}

func conditionEqualsIgnoreLastTransitionTime(a, b crdv1alpha1.PacketCaptureCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	conditionSliceEqualsIgnoreLastTransitionTime,
)

func packetCaptureStatusEqual(oldStatus, newStatus crdv1alpha1.PacketCaptureStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func conditionSliceEqualsIgnoreLastTransitionTime(as, bs []crdv1alpha1.PacketCaptureCondition) bool {
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !conditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}

func mergeConditions(oldConditions, newConditions []crdv1alpha1.PacketCaptureCondition) []crdv1alpha1.PacketCaptureCondition {
	finalConditions := make([]crdv1alpha1.PacketCaptureCondition, 0)
	newConditionMap := make(map[crdv1alpha1.PacketCaptureConditionType]crdv1alpha1.PacketCaptureCondition)
	addedConditions := sets.New[string]()
	for _, condition := range newConditions {
		newConditionMap[condition.Type] = condition
	}
	for _, oldCondition := range oldConditions {
		newCondition, exists := newConditionMap[oldCondition.Type]
		if !exists {
			finalConditions = append(finalConditions, oldCondition)
			continue
		}
		// Use the original Condition if the only change is about lastTransition time
		if conditionEqualsIgnoreLastTransitionTime(newCondition, oldCondition) {
			finalConditions = append(finalConditions, oldCondition)
		} else {
			// Use the latest Condition.
			finalConditions = append(finalConditions, newCondition)
		}
		addedConditions.Insert(string(newCondition.Type))
	}
	for key, newCondition := range newConditionMap {
		if !addedConditions.Has(string(key)) {
			finalConditions = append(finalConditions, newCondition)
		}
	}
	return finalConditions
}
