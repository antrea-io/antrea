# Running the Antrea Multicluster end-to-end tests

## Creating the test Kubernetes ClusterSet

The tests must be run on an actual Kubernetes cluster set, and there must be at least three clusters. We can create the clusters using [kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm) or following [the e2e test instructions](https://github.com/antrea-io/antrea/blob/main/test/e2e/README.md) or through other ways.

The three clusters are called leader cluster, west cluster and east cluster. Pod CIDR of each cluster should not be the same. For example, Pod CIDRs could be `192.168.0.1/22`,`192.168.4.1/22` and `192.168.8.1/22` in three clusters.

## Running the tests

Make sure that your clusters are provisioned and that the Antrea build artifacts are pushed to all the Nodes. If you install the multicluster manually, you can then run the tests from the top-level directory with `go test -v antrea.io/antrea/multicluster/test/e2e` or you can just run `bash ci/jenkins/test-mc.sh --testcase e2e`.

When you use `test-mc.sh`, make sure your kubeconfig files of the clusters in the specific path of the script, or you can change the parameter `MULTICLUSTER_KUBECONFIG_PATH` and other parameters to your own path in the script.
