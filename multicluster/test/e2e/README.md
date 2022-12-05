# Running the Antrea Multicluster end-to-end tests

## Creating the test Kubernetes ClusterSet

The tests can run either on an actual Kubernetes ClusterSet or a ClusterSet with
Kind clusters, and there must be three clusters. You can create the clusters
using [kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm)
or following [the e2e test instructions](https://github.com/antrea-io/antrea/blob/main/test/e2e/README.md)
or through other ways.

By default, the three clusters used in the e2e tests are called `leader`, `west`
and `east`. If you plan to use your own existing Kubernetes clusters, please make
sure you save kubeconfig files for three clusters with the same name as cluster's
name, and Service CIDR of each cluster must not overlap. For example, Service
CIDRs could be `10.96.10.0/24`, `10.96.20.0/24`, and `10.96.30.0/24` for three clusters.

## Running the tests

Make sure that your clusters are provisioned and the Antrea build artifacts are
uploaded to all the Nodes. If you install the Multi-cluster Controller manually,
you can run the tests from the top-level directory with `go test -v antrea.io/antrea/multicluster/test/e2e --mc-gateway`
or run `bash ci/jenkins/test-mc.sh --testcase e2e --mc-gateway`. If you'd like
to run test with Kind clusters, you can run `bash ci/jenkins/test-mc.sh --testcase e2e --mc-gateway --kind`.
The command will create three Kind clusters and deploy Multi-cluster Controllers
into the Kind clusters before running e2e tests.

When you use `test-mc.sh`, make sure your kubeconfig files of the clusters are placed
in the right path. The default path is `${MULTICLUSTER_KUBECONFIG_PATH}`. Please
change the parameter `MULTICLUSTER_KUBECONFIG_PATH` to the right path where you place
kubeconfig files. Sample commands are like below:

```bash
export WORKSPACE=`pwd`
export MULTICLUSTER_KUBECONFIG_PATH="`pwd`/.kube"
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test-mc.sh --testcase e2e --registry ${DOCKER_REGISTRY} --mc-gateway [--kind]
```

Notes: if you pass `--kind`, `test-mc.sh` will write kubeconfig files to the given path
`${MULTICLUSTER_KUBECONFIG_PATH}` automatically.
