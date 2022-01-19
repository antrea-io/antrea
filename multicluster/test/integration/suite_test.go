// Copyright 2021 Antrea Authors.
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

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	mcsscheme "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/scheme"

	// mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
	antreamcscheme "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/scheme"
	"antrea.io/antrea/pkg/signals"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	timeout  = time.Second * 15
	interval = time.Second * 1
)

var (
	cfg             *rest.Config
	k8sClient       client.Client
	testEnv         *envtest.Environment
	k8sServerURL    string
	LocalClusterID  = "cluster-a"
	LeaderNamespace = "leader-ns"
	clusterSetID    = "test-clusterset"
	testNamespace   = "testns"
	testNSForStale  = "testns-stale"

	testNS = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}

	testNSStale = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNSForStale,
		},
	}

	leaderNS = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: LeaderNamespace,
		},
	}
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	os.Setenv("KUBECONFIG", "/tmp/mc-integration-kubeconfig")
	By("bootstrapping test environment")
	useExistingCluster := true
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases"), filepath.Join("..", "..", "config", "crd", "k8smcs")},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    &useExistingCluster,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	scheme := runtime.NewScheme()
	err = mcsscheme.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())
	err = antreamcscheme.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())
	err = k8sscheme.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())
	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	Expect(err).ToNot(HaveOccurred())
	k8sServerURL = testEnv.Config.Host
	ctx := context.Background()

	By("Creating MemberClusterSetReconciler")
	k8sClient.Create(ctx, leaderNS)
	k8sClient.Create(ctx, testNS)
	k8sClient.Create(ctx, testNSStale)
	clusterSetReconciler := &multiclustercontrollers.MemberClusterSetReconciler{
		Client:    k8sManager.GetClient(),
		Scheme:    k8sManager.GetScheme(),
		Namespace: LeaderNamespace,
	}
	err = clusterSetReconciler.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	By("Creating ServiceExportReconciler")
	svcExportReconciler := multiclustercontrollers.NewServiceExportReconciler(
		k8sManager.GetClient(),
		k8sManager.GetScheme(),
		&clusterSetReconciler.RemoteCommonAreaManager)
	err = svcExportReconciler.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// import reconciler will be started from RemoteCommonArea after
	// configureClusterSet finishes

	By("Creating StaleController")
	stopCh := signals.RegisterSignalHandlers()
	staleController := multiclustercontrollers.NewStaleController(
		k8sManager.GetClient(),
		k8sManager.GetScheme(),
		&clusterSetReconciler.RemoteCommonAreaManager)

	go staleController.Run(stopCh)
	// Make sure to trigger clean up process every 5 seconds
	// otherwise staleController will only run once before test case is ready to run.
	go func() {
		for {
			staleController.Enqueue()
			time.Sleep(5 * time.Second)
		}
	}()

	By("Creating ResourceExportReconciler")
	resExportReconciler := multiclustercontrollers.NewResourceExportReconciler(
		k8sManager.GetClient(),
		k8sManager.GetScheme())
	err = resExportReconciler.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		By("Start Manager")
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()
	configureClusterSet()
}, 60)

func configureClusterSet() {
	clusterIDClaim := &mcsv1alpha1.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: LeaderNamespace,
			Name:      "local-cluster-id",
		},
		Name:  "id.k8s.io",
		Value: LocalClusterID,
	}
	clusterSetIDClaim := &mcsv1alpha1.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: LeaderNamespace,
			Name:      "clusterset-id",
		},
		Name:  "clusterSet.k8s.io",
		Value: clusterSetID,
	}
	clusterSet := &mcsv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: LeaderNamespace,
			Name:      clusterSetID,
		},
		Spec: mcsv1alpha1.ClusterSetSpec{
			Leaders: []mcsv1alpha1.MemberCluster{
				{
					ClusterID: LocalClusterID,
					Secret:    "access-token",
					Server:    k8sServerURL,
				},
			},
			Members: []mcsv1alpha1.MemberCluster{
				{
					ClusterID: LocalClusterID,
				},
			},
			Namespace: LeaderNamespace,
		},
	}
	ctx := context.Background()
	err := k8sClient.Create(ctx, clusterIDClaim, &client.CreateOptions{})
	Expect(err == nil).Should(BeTrue())
	err = k8sClient.Create(ctx, clusterSetIDClaim, &client.CreateOptions{})
	Expect(err == nil).Should(BeTrue())
	err = k8sClient.Create(ctx, clusterSet, &client.CreateOptions{})
	Expect(err == nil).Should(BeTrue())
	Eventually(func() bool {
		memberAnnounce := &mcsv1alpha1.MemberClusterAnnounce{}
		err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: "member-announce-from-cluster-a"}, memberAnnounce)
		return err == nil
	}, timeout, interval).Should(BeTrue())
}

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	k8sClient.Delete(context.TODO(), testNS)
	k8sClient.Delete(context.TODO(), testNSStale)
	k8sClient.Delete(context.TODO(), leaderNS)
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
