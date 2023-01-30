package app

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	fakeapiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	clientset "k8s.io/client-go/kubernetes"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	componentbaseconfig "k8s.io/component-base/config"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	fakeaggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	"antrea.io/antrea/cmd/antrea-agent/app/options"
	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	crdfake "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/signals"
)

func TestRunAgentController(t *testing.T) {
	goExec = func(function func(stopCh <-chan struct{}), stopCh <-chan struct{}) {
		pc := reflect.ValueOf(function).Pointer()
		funcName := runtime.FuncForPC(pc).Name()
		t.Logf("fake function %s running", funcName)
	}
	apiServerRun = func(function func(stopCh <-chan struct{}) error, stopCh <-chan struct{}) {
		t.Log("fake APIServer running")
	}
	goExecWithCtx = func(function func(ctx context.Context), ctx context.Context) {
		t.Log("fake APIServer running")
	}
	createK8sClient = func(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (
		clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, apiextensionclientset.Interface, mcclientset.Interface, error) {
		aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
		apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
		return fakeclientset.NewSimpleClientset(), aggregatorClientset, crdfake.NewSimpleClientset(), apiExtensionClient, mcfake.NewSimpleClientset(), nil
	}

	opts := options.NewOptions()
	if err := opts.Complete(); err != nil {
		t.Errorf("Complete antrea controller config error: %v", err)
	}

	newOVSDBConnection = func(address string) (*ovsdb.OVSDB, ovsconfig.Error) {

		return &ovsdb.OVSDB{}, nil
	}

	go func() {
		time.Sleep(time.Second)
		signals.GenerateStopSignal()
	}()
	if err := Run(opts); err != nil {
		t.Errorf("Run antrea controller error: %v", err)
	}
}
