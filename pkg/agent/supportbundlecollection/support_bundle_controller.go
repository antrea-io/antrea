// Copyright 2022 Antrea Authors
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

package supportbundlecollection

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/spf13/afero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"

	"antrea.io/antrea/pkg/agent/client"
	agentquerier "antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/apis/controlplane"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/support"
	"antrea.io/antrea/pkg/util/compress"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/sftp"
)

type ProtocolType string

const (
	sftpProtocol ProtocolType = "sftp"

	controllerName = "SupportBundleCollectionController"
)

var (
	emptyWatch      = watch.NewEmptyWatch()
	defaultFS       = afero.NewOsFs()
	defaultExecutor = exec.New()
	// Declared as variable for testing.
	newAgentDumper = support.NewAgentDumper
)

type SupportBundleController struct {
	nodeName                     string
	supportBundleNodeType        controlplane.SupportBundleCollectionNodeType
	namespace                    string
	antreaClientGetter           client.AntreaClientProvider
	queue                        workqueue.TypedInterface[string]
	supportBundleCollection      *cpv1b2.SupportBundleCollection
	supportBundleCollectionMutex sync.RWMutex
	ovsCtlClient                 ovsctl.OVSCtlClient
	aq                           agentquerier.AgentQuerier
	npq                          querier.AgentNetworkPolicyInfoQuerier
	v4Enabled                    bool
	v6Enabled                    bool
	sftpUploader                 sftp.Uploader
}

func NewSupportBundleController(nodeName string,
	supportBundleNodeType controlplane.SupportBundleCollectionNodeType,
	namespace string,
	antreaClientGetter client.AntreaClientProvider,
	ovsCtlClient ovsctl.OVSCtlClient,
	aq agentquerier.AgentQuerier,
	npq querier.AgentNetworkPolicyInfoQuerier,
	v4Enabled,
	v6Enabled bool) *SupportBundleController {
	c := &SupportBundleController{
		nodeName:              nodeName,
		supportBundleNodeType: supportBundleNodeType,
		namespace:             namespace,
		antreaClientGetter:    antreaClientGetter,
		queue: workqueue.NewTypedWithConfig(workqueue.TypedQueueConfig[string]{
			Name: "supportbundle",
		}),
		ovsCtlClient: ovsCtlClient,
		aq:           aq,
		npq:          npq,
		v4Enabled:    v4Enabled,
		v6Enabled:    v6Enabled,
		sftpUploader: sftp.NewUploader(),
	}
	return c
}

func (c *SupportBundleController) watchSupportBundleCollections() {
	klog.Info("Starting watch for SupportBundleCollections")
	antreaClient, err := c.antreaClientGetter.GetAntreaClient()
	if err != nil {
		klog.ErrorS(err, "Failed to get antrea client")
		return
	}
	nodeNameSelector := c.nodeName
	if c.supportBundleNodeType == controlplane.SupportBundleCollectionNodeTypeExternalNode {
		nodeNameSelector = k8s.NamespacedName(c.namespace, c.nodeName)
	}
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", nodeNameSelector).String(),
	}
	watcher, err := antreaClient.ControlplaneV1beta2().SupportBundleCollections().Watch(context.TODO(), options)
	if err != nil {
		klog.ErrorS(err, "Failed to start watch for SupportBundleCollections")
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log warning otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.ErrorS(nil, "Failed to start watch for SupportBundleCollections, please ensure antrea service is reachable for the agent")
		return
	}

	klog.Info("Started watch for SupportBundleCollections")
	eventCount := 0
	defer func() {
		klog.InfoS("Stopped watch for SupportBundleCollections", "totalItemsReceived", eventCount)
		watcher.Stop()
	}()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Bookmark:
				klog.V(2).Info("Received Bookmark event")
			case watch.Added:
				c.addSupportBundleCollection(event.Object.(*cpv1b2.SupportBundleCollection))
				klog.InfoS("Added SupportBundleCollection", "name", event.Object.(*cpv1b2.SupportBundleCollection).Name)
			case watch.Deleted:
				c.deleteSupportBundleCollection(event.Object.(*cpv1b2.SupportBundleCollection))
				klog.InfoS("Deleted SupportBundleCollection", "name", event.Object.(*cpv1b2.SupportBundleCollection).Name)
			default:
				klog.ErrorS(nil, "Received unknown event", "event", event.Type)
				return
			}
			eventCount++
		}
	}
}

func (c *SupportBundleController) addSupportBundleCollection(supportBundle *cpv1b2.SupportBundleCollection) {
	c.supportBundleCollectionMutex.Lock()
	c.supportBundleCollection = supportBundle
	c.supportBundleCollectionMutex.Unlock()
	c.queue.Add(supportBundle.Name)
}

func (c *SupportBundleController) deleteSupportBundleCollection(supportBundle *cpv1b2.SupportBundleCollection) {
	c.supportBundleCollectionMutex.Lock()
	c.supportBundleCollection = nil
	c.supportBundleCollectionMutex.Unlock()
	c.queue.Add(supportBundle.Name)
}

func (c *SupportBundleController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	go wait.NonSlidingUntil(c.watchSupportBundleCollections, 5*time.Second, stopCh)

	go wait.Until(c.worker, time.Second, stopCh)
	<-stopCh
}

func (c *SupportBundleController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *SupportBundleController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncSupportBundleCollection(key); err == nil {
		klog.InfoS("Successfully synced support bundle", "name", key)
	} else {
		// Skip retrying as the time may not meet the requirements for SupportBundle.
		klog.ErrorS(err, "Error syncing SupportBundleCollection", "name", key)
	}
	return true
}

func (c *SupportBundleController) syncSupportBundleCollection(key string) error {
	klog.InfoS("Processing support bundle collection", "name", key)
	supportBundle := func() *cpv1b2.SupportBundleCollection {
		c.supportBundleCollectionMutex.RLock()
		defer c.supportBundleCollectionMutex.RUnlock()
		return c.supportBundleCollection
	}()
	if supportBundle == nil {
		return nil
	}

	err := c.generateSupportBundle(supportBundle)
	if err != nil {
		if updateErr := c.updateSupportBundleCollectionStatus(key, false, err); updateErr != nil {
			return fmt.Errorf("failed to update failed collection status: %w", updateErr)
		}
		return fmt.Errorf("failed to generate support bundle: %w", err)
	}
	if updateErr := c.updateSupportBundleCollectionStatus(key, true, err); updateErr != nil {
		return fmt.Errorf("failed to update complete collection status: %w", updateErr)
	}

	return nil
}

func (c *SupportBundleController) generateSupportBundle(supportBundle *cpv1b2.SupportBundleCollection) error {
	klog.V(2).InfoS("Generating support bundle collection", "name", supportBundle.Name)
	basedir, err := afero.TempDir(defaultFS, "", "bundle_tmp_")
	if err != nil {
		return fmt.Errorf("error when creating temp dir: %w", err)
	}
	defer defaultFS.RemoveAll(basedir)

	agentDumper := newAgentDumper(defaultFS, defaultExecutor, c.ovsCtlClient, c.aq, c.npq, supportBundle.SinceTime, c.v4Enabled, c.v6Enabled)
	if err = agentDumper.DumpLog(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpHostNetworkInfo(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpFlows(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpGroups(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpNetworkPolicyResources(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpAgentInfo(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpHeapPprof(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpGoroutinePprof(basedir); err != nil {
		return err
	}
	if err = agentDumper.DumpOVSPorts(basedir); err != nil {
		return err
	}

	outputFile, err := afero.TempFile(defaultFS, "", "bundle_*.tar.gz")
	if err != nil {
		return fmt.Errorf("error when creating temp file: %w", err)
	}
	defer func() {
		if err = outputFile.Close(); err != nil {
			klog.ErrorS(err, "Error when closing output tar file")
		}
		if err = defaultFS.Remove(outputFile.Name()); err != nil {
			klog.ErrorS(err, "Error when removing output tar file", "file", outputFile.Name())
		}

	}()
	klog.V(2).InfoS("Compressing support bundle collection", "name", supportBundle.Name)
	if _, err = compress.PackDir(defaultFS, basedir, outputFile); err != nil {
		return fmt.Errorf("error when packaging support bundle: %w", err)
	}

	return c.uploadSupportBundle(supportBundle, outputFile)
}

func (c *SupportBundleController) uploadSupportBundle(supportBundle *cpv1b2.SupportBundleCollection, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading support bundle collection", "name", supportBundle.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload support bundle while getting uploader: %v", err)
	}

	if _, err := outputFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to upload to the file server while setting offset: %v", err)
	}
	fileName := c.nodeName + "_" + supportBundle.Name + ".tar.gz"
	cfg, err := sftp.GetSSHClientConfig(
		supportBundle.Authentication.BasicAuthentication.Username,
		supportBundle.Authentication.BasicAuthentication.Password,
		supportBundle.FileServer.HostPublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to generate SSH client config: %w", err)
	}
	return uploader.Upload(supportBundle.FileServer.URL, fileName, cfg, outputFile)
}

func (c *SupportBundleController) getUploaderByProtocol(protocol ProtocolType) (sftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *SupportBundleController) updateSupportBundleCollectionStatus(key string, complete bool, genErr error) error {
	antreaClient, err := c.antreaClientGetter.GetAntreaClient()
	if err != nil {
		return fmt.Errorf("failed to get antrea client: %w", err)
	}
	var errMsg string
	if genErr != nil {
		errMsg = genErr.Error()
	}
	if updateErr := antreaClient.ControlplaneV1beta2().SupportBundleCollections().UpdateStatus(context.TODO(), key, &cpv1b2.SupportBundleCollectionStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name: key,
		},
		Nodes: []cpv1b2.SupportBundleCollectionNodeStatus{
			{
				NodeName:      c.nodeName,
				NodeNamespace: c.namespace,
				NodeType:      string(c.supportBundleNodeType),
				Completed:     complete,
				Error:         errMsg,
			},
		},
	}); updateErr != nil {
		return fmt.Errorf("failed to update collection status for bundle: %s, err: %w", key, err)
	}
	return nil
}
