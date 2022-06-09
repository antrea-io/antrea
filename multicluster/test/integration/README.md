# Integration Test Framework

The integration test framework for Antrea multi-cluster is mainly using [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest)
which is provided by `controller-runtime`. There is an online book
about kubebuilder that describes a few steps about [how to configure envtest](https://book.kubebuilder.io/reference/envtest.html)
for integration tests. `envtest` supports using an existing cluster to run integration
test by setting a config `USE_EXISTING_CLUSTER`. In Antrea multi-cluster, we choose to use
an existing cluster to run tests with a real control plane and dependent controllers
like Service, Endpoints controllers etc.

## Running the Antrea Multi-cluster Integration tests

The tests must be run on an real Kubernetes cluster. At the moment, you can
simply run `make test-integration` in `antrea/multicluster` folder. It will
create a Kind cluster named `antrea-integration` and execute the integration
codes.

if you'd like to run the integration test in an existing Kubernetes cluster, you
can save your kubeconfig file as `mc-integration-kubeconfig` in `/tmp` directly,
the integration test codes will read the file `/tmp/mc-integration-kubeconfig` by
default, then run below commands:

```bash
export KUBECONFIG=/tmp/mc-integration-kubeconfig
kubectl create namespace leader-ns
kubectl apply -f test/integration/cluster-admin.yml
go test -coverpkg=antrea.io/antrea/multicluster/controllers/multicluster/... -coverprofile=../.coverage/coverage-integration.txt -covermode=atomic -cover antrea.io/antrea/multicluster/test/integration/...
```

You should be able to see the overall results from terminal, if you'd like to
check more details, you can go check the file `.coverage/coverage-integration.txt`.
