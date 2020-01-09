package main

import (
	"fmt"
	"os"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/cleanup"
	"github.com/vmware-tanzu/antrea/pkg/apis/cleanup/v1beta1"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/signals"
)

const (
	ExitCodeSuccess = iota
	// ExitCodeSetupFailure indicates that we could not attempt cleanup
	// because of a failed precondition, e.g. NODE_NAME environment variable
	// was not set or we could not create the K8s go client.
	ExitCodeSetupFailure
	// ExitCodeCleanupFailure indicates that an error occurred during the
	// cleanup process.
	ExitCodeCleanupFailure
	// ExitCodeStatusReportFailure indicates that we could not create /
	// update the CRD to report to the cleanup controller our status.
	ExitCodeStatusReportFailure
)

func getCRDName() (string, error) {
	crdName := os.Getenv("NODE_NAME")
	if crdName == "" {
		return "", fmt.Errorf("NODE_NAME is not set")
	}
	return crdName, nil
}

type cleanupStatus struct {
	success bool
	msg     string
}

func newCleanupStatus(success bool, msg string) cleanupStatus {
	return cleanupStatus{
		success: success,
		msg:     msg,
	}
}

func createOrUpdateCRD(client crdclientset.Interface, crdName string, status cleanupStatus) error {
	cleanupCRD := &v1beta1.CleanupStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		Success: status.success,
		Msg:     status.msg,
	}

	klog.Infof("Creating CRD %s: %v", crdName, cleanupCRD)
	_, err := client.CleanupV1beta1().CleanupStatuses().Create(cleanupCRD)
	if err != nil && apierrors.IsAlreadyExists(err) {
		_, err = client.CleanupV1beta1().CleanupStatuses().Update(cleanupCRD)
	}
	return err
}

func doCleanupIfNeeded() cleanupStatus {
	if isNeeded, err := cleanup.IsAgentCleanupNeeded(); err != nil {
		return newCleanupStatus(false, err.Error())
	} else if !isNeeded {
		klog.Infof("No cleanup needed")
		return newCleanupStatus(true, "no cleanup needed")
	}

	if err := cleanup.AgentCleanup(); err != nil {
		klog.Errorf("Error during cleanup process: %v", err)
		return newCleanupStatus(false, err.Error())
	}
	klog.Infof("Cleanup succeeded")
	return newCleanupStatus(true, "cleanup succeeded")
}

func cleanupAndWaitForController() int {
	logs.InitLogs()
	defer logs.FlushLogs()

	klog.Infof("Antrea Cleanup Agent")

	crdName, err := getCRDName()
	if err != nil {
		klog.Errorf("Cannot generate CRD name: %v", err)
		return ExitCodeSetupFailure
	}

	_, crdClient, err := k8s.CreateClients(componentbaseconfig.ClientConnectionConfiguration{})
	if err != nil {
		klog.Errorf("Error creating K8s client: %v", err)
		return ExitCodeSetupFailure
	}

	status := doCleanupIfNeeded()
	if err := createOrUpdateCRD(crdClient, crdName, status); err != nil {
		klog.Errorf("Error when creating CRD: %v", err)
		return ExitCodeStatusReportFailure
	}

	klog.Infof("Waiting for exit signal")
	stopCh := signals.RegisterSignalHandlers()
	<-stopCh

	if !status.success {
		return ExitCodeCleanupFailure
	}
	return ExitCodeSuccess
}

func main() {
	os.Exit(cleanupAndWaitForController())
}
