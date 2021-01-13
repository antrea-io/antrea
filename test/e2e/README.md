# Running the Antrea end-to-end tests

## Creating the test Kubernetes cluster

The tests must be run on an actual Kubernetes cluster. At the moment, we require
the cluster to be created using [Vagrant](https://www.vagrantup.com/) and the
provided [Vagrantfile](infra/vagrant/Vagrantfile), which you can do by following
the instructions below.

### Creating the test Kubernetes cluster with Vagrant

We use Vagrant to provision two Virtual Machines (one Kubernetes control-plane
Node and one worker Node). The required software is installed on each machine
with [Ansible](https://www.ansible.com/). By default the Vagrantfile uses
[VirtualBox](https://www.virtualbox.org/) but you should be able to edit the
file to use your favorite Vagrant provider.

#### Dependencies

We require the following to be installed on your host machine:

* `vagrant` (`>= 2.0.0`)
* `ansible` (`>= 2.4.0`)
* `virtualbox` (See supported versions
  [here](https://www.vagrantup.com/docs/virtualbox/)).

##### Ubuntu 18.04 (or later)

You can install all dependencies with `sudo apt install vagrant ansible
virtualbox`.

##### Mac OS

You can install all the dependencies with [brew](https://brew.sh/):

* `brew cask install virtualbox`
* `brew cask install vagrant`
* `brew install ansible`

If an action is required on your part, `brew` will let you know in its log
messages.

#### Managing the cluster

Use the following Bash scripts to manage the Kubernetes Nodes with Vagrant:

* `./infra/vagrant/provision.sh`: create the required VMs and provision them
* `./infra/vagrant/push_antrea.sh`: load Antrea Docker image to each Node, along
  with the Antrea deployment YAML
* `./infra/vagrant/suspend.sh`: suspend all Node VMs
* `./infra/vagrant/resume.sh`: resume all Node VMs
* `./infra/vagrant/destroy.sh`: destoy all Node VMs, you will need to run
  `provision.sh` again to create a new cluster

Note that `./infra/vagrant/provision.sh` can take a while to complete but it
only needs to be run once.

#### Debugging

You can SSH into any of the Node VMs using `vagrant ssh [Node name]` (must be
run from the `infra/vagrant` directory. The control-plane Node is named
`k8s-node-control-plane` and the worker Nodes are named `k8s-node-worker-<N>`
(for a single worker Node, the name is `k8s-node-worker-1`. `kubectl` is
installed on all the Nodes.

The
[kubeconfig](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/)
file for the cluster can also be found locally on your machine at
`./infra/vagrant/playbook/kube/config`. If you install
[`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/) locally and
set the `KUBECONFIG` environment variable to the absolute path of this
kubeconfig file, you can run commands against your test cluster created with
Vagrant. For example:

```bash
cd <directory containing this README file>
export KUBECONFIG=`pwd`/infra/vagrant/playbook/kube/config
kubectl cluster-info
```

## Running the tests

Make sure that your cluster was provisioned and that the Antrea build artifacts
were pushed to all the Nodes. You can then run the tests from the top-level
directory with `go test -v -timeout=30m github.com/vmware-tanzu/antrea/test/e2e`
(the `-v` enables verbose output).

If you are running the test for the first time and are using the scripts we
provide under `infra/vagrant` to provision your Kubernetes cluster, you will
therefore need the following steps:

1. `./infra/vagrant/provision.sh`
2. `make`
3. `./infra/vagrant/push_antrea.sh`
4. `go test -v -timeout=30m github.com/vmware-tanzu/antrea/test/e2e`

If you need to test an updated version of Antrea, just run
`./infra/vagrant/push_antrea.sh` and then run the tests again.

By default, if a test case fails, we write some useful debug information to a
temporary directory on disk. This information includes the detailed description
(obtained with `kubectl describe`) and the logs (obtained with `kubectl logs`)
of each Antrea Pod at the time the test case exited. When running the tests in
verbose mode (i.e. with `-v`), the test logs will tell you the location of that
temporary directory. You may also choose your own directory using
`--logs-export-dir`. For example:

```bash
mkdir antrea-test-logs
go test -count=1 -v -run=TestDeletePod github.com/vmware-tanzu/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs
```

If the user provides a log directory which was used for a previous run, existing
contents (subdirectories for each test case) will be overridden.
By default the description and logs for Antrea Pods are only written to disk if a
test fails. You can choose to dump this information unconditionally with
`--logs-export-on-success`.

### Testing the Prometheus Integration

The Prometheus integration tests can be run as part of the e2e tests when
enabled explicitly.

* To load Antrea into the cluster with Prometheus enabled, use:
`./infra/vagrant/push_antrea.sh --prometheus`
* To run the Prometheus tests within the e2e suite, use:
`go test -v github.com/vmware-tanzu/antrea/test/e2e --prometheus`

## Running the e2e tests on a Kind cluster

The simplest way is to run the following command:

```bash
./ci/kind/test-e2e-kind.sh [options]
```

It will set up a two worker Node Kind cluster to run the e2e tests, and destroy
the cluster after the tests stop (succeed or fail). `kubectl` needs to be
present in your `PATH` to set up the test cluster. For more information on the
usage of this script and the options, run:

```bash
./ci/kind/test-e2e-kind.sh --help
```

You can also run the e2e tests with an existing Kind cluster. Refer to this
[document](/docs/kind.md) for instructions on how to create a Kind cluster and
use Antrea as the CNI. You need at least one control-plane Node and one worker
Node. Before running the Go e2e tests, you will also need to copy the Antrea
manifest to the control-plane Docker container:

```bash
./hack/generate-manifest.sh --kind | docker exec -i kind-control-plane dd of=/root/antrea.yml
go test -v github.com/vmware-tanzu/antrea/test/e2e -provider=kind
```

As part of code development, if you want to run the tests with local changes,
then make the code changes on the local repo and
[build the image](../../CONTRIBUTING.md#building-and-testing-your-change).
You can load the new image into the kind cluster using the command below:

```bash
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:latest --name <kind_cluster_name>
```

## Running the performance test

To run all benchmarks, without the standard e2e tests:

```bash
go test -v -timeout=30m -run=XXX -bench=. \
    github.com/vmware-tanzu/antrea/test/e2e \
    --performance.http.concurrency=16
```

The above command uses `-run=XXX` to deselect all `Test*` tests and uses `-bench=.` to select
all `Benchmark*` tests. Since performance tests take a while to complete, you need to extend
the timeout duration `-timeout` from the default `10m` to a longer one like `30m`.

If you would like to run the performance tests in a different scale, you could run:

```bash
go test -v -timeout=30m -run=XXX -bench=BenchmarkCustomize \
    github.com/vmware-tanzu/antrea/test/e2e \
    --performance.http.requests=5000 \
    --performance.http.policy_rules=1000 \
    --performance.http.concurrency=16
```

All flags of performance tests includes:

* `performance.http.concurrency (int)`: Number of allowed concurrent http requests (default 1)
* `performance.http.requests (int)`: Total Number of http requests
* `performance.http.policy_rules (int)`: Number of CIDRs in the network policy
* `performance.realize.timeout (duration)`: Timeout of the realization of network policies (default 5m0s)
