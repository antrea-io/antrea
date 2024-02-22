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

package certificatesigningrequest

import (
	"context"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	csrlisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	approvingControllerName = "CertificateSigningRequestApprovingController"
)

type approver interface {
	recognize(csr *certificatesv1.CertificateSigningRequest) bool
	verify(csr *certificatesv1.CertificateSigningRequest) (bool, error)
	name() string
}

// CSRApprovingController is responsible for approving CertificateSigningRequests.
type CSRApprovingController struct {
	client          clientset.Interface
	csrInformer     cache.SharedIndexInformer
	csrLister       csrlisters.CertificateSigningRequestLister
	csrListerSynced cache.InformerSynced
	queue           workqueue.RateLimitingInterface
	approvers       []approver
}

// NewCSRApprovingController returns a new *CSRApprovingController.
func NewCSRApprovingController(client clientset.Interface, csrInformer cache.SharedIndexInformer, csrLister csrlisters.CertificateSigningRequestLister) *CSRApprovingController {
	c := &CSRApprovingController{
		client:          client,
		csrInformer:     csrInformer,
		csrLister:       csrLister,
		csrListerSynced: csrInformer.HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "certificateSigningRequest"),
		approvers: []approver{
			newIPsecCSRApprover(client),
		},
	}
	csrInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueCertificateSigningRequest,
		},
		resyncPeriod,
	)
	return c
}

// Run begins watching and syncing of the CSRApprovingController.
func (c *CSRApprovingController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting " + approvingControllerName)
	defer klog.InfoS("Shutting down " + approvingControllerName)

	cacheSyncs := []cache.InformerSynced{c.csrListerSynced}
	if !cache.WaitForNamedCacheSync(approvingControllerName, stopCh, cacheSyncs...) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *CSRApprovingController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *CSRApprovingController) enqueueCertificateSigningRequest(obj interface{}) {
	csr, ok := obj.(*certificatesv1.CertificateSigningRequest)
	if !ok {
		return
	}
	c.queue.Add(csr.Name)
}

func (c *CSRApprovingController) syncCSR(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).InfoS("Finished syncing CertificateSigningRequest", "name", key, "duration", d)
	}()

	csr, err := c.csrLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	// The spec will not be updated by antrea-agent once it is approved or denied.
	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}
	for _, a := range c.approvers {
		if a.recognize(csr) {
			approved, err := a.verify(csr)
			if err != nil {
				return err
			}
			if approved {
				toUpdate := csr.DeepCopy()
				appendApprovalCondition(toUpdate, fmt.Sprintf("Automatically approved by %s", a.name()))
				_, err = c.client.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.Background(), toUpdate.Name, toUpdate, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("error updating approval for csr: %w", err)
				}
				return nil
			}
		}
	}
	return nil
}

func appendApprovalCondition(csr *certificatesv1.CertificateSigningRequest, message string) {
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:    certificatesv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: message,
	})
}

func (c *CSRApprovingController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.syncCSR(key.(string))
	if err != nil {
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync CertificateSigningRequest", "CertificateSigningRequest", key)
		return true
	}
	c.queue.Forget(key)
	return true
}
