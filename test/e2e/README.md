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

* `brew install --cask virtualbox`
* `brew install --cask vagrant`
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

##### IPv6 cluster

To test Antrea IPv6 support, an IPv6-only cluster can be created, by
provisioning a private IPv6 network to connect Kubernetes Nodes, instead of a
private IPv4 network. You simply need to invoke `./infra/vagrant/provision.sh`
with `--ip-family v6`. This option can be used even if the host machine does not
support IPv6 itself. Note however that the Nodes do not have public IPv6
connectivity; they can still connect to the Internet using IPv4, which means
that Docker images can be pulled without issue. Similarly, Pods (which only
support IPv6) cannot connect to the Internet. To avoid issues when running
Kubernetes conformance tests, we configure a proxy on the control-plane Node for
all DNS traffic. While CoreDNS will reply to cluster local DNS queries directly,
all other queries will be forwarded to the proxy over IPv6, and the proxy will
then forward them to the default resolver for the Node (this time over
IPv4). This means that all DNS queries from the Pods should succeed, even though
the returned public IP addresses (IPv4 and / or IPv6) are not accessible.

You may need more recent versions of the dependencies (virtualbox, vagrant,
ansible) than the ones listed above when creating an IPv6 cluster. The following
versions were tested successfully:

* `vagrant 2.2.14`
* `ansible 2.9.18`
* `virtualbox 5.2`

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

#### Known issues

##### The IP address configured for the host-only network is not within the allowed ranges

With recent versions of VirtualBox (> 6.1.26), you may see the following error
when running `./infra/vagrant/provision.sh`:

```text
The IP address configured for the host-only network is not within the
allowed ranges. Please update the address used to be within the allowed
ranges and run the command again.

  Address: 192.168.77.100
  Ranges: 192.168.56.0/21

Valid ranges can be modified in the /etc/vbox/networks.conf file. For
more information including valid format see:

  https://www.virtualbox.org/manual/ch06.html#network_hostonly
```

To workaround this issue, you can either:

* downgrade your VirtualBox version to 6.1.26
* create a `/etc/vbox/networks.conf` file with the following contents:

```text
* 192.168.77.0/24
```

## Running the tests

Make sure that your cluster was provisioned and that the Antrea build artifacts
were pushed to all the Nodes. You can then run the tests from the top-level
directory with `go test -v -timeout=30m antrea.io/antrea/test/e2e`
(the `-v` enables verbose output).

### Running the tests with vagrant

If you are running the test for the first time and are using the scripts we
provide under `infra/vagrant` to provision your Kubernetes cluster, you will
therefore need the following steps:

1. `./infra/vagrant/provision.sh`
2. `make`
3. `./infra/vagrant/push_antrea.sh`
4. `go test -v -timeout=30m antrea.io/antrea/test/e2e`

If you need to test an updated version of Antrea, just run
`./infra/vagrant/push_antrea.sh` and then run the tests again.

### Running the tests with remote (existing K8s cluster)

If you already have a K8s cluster, these steps should be followed to run the e2e tests.

First, you should provide the ssh information for each Node in the cluster. Here is an example:

```text
Host <Control-Plane-Node>
    HostName <Control-Plane-IP>
    Port 22
    user ubuntu
    IdentityFile /home/ubuntu/.ssh/id_rsa
Host <Worker-Node>
    HostName <Worker-Node-IP>
    Port 22
    user ubuntu
    IdentityFile /home/ubuntu/.ssh/id_rsa
```

Make sure the `Host` entry for each Node matches the K8s Node name. The `Port` is the port used by the ssh service on the Node.

Besides, you should add the public key to `authorized_keys` of each Node and set `PubkeyAuthentication` of ssh service to `yes`.

Second, the kubeconfig of the cluster should be copied to the right location, e.g. `$HOME/.kube/config` or the path specified by `-remote.kubeconfig`.

Third, the `antrea.yml` (and `antrea-windows.yml` if the cluster has Windows Nodes) should be put under the `$HOME` directory of the control-plane Node.

Now you can start e2e tests using the command below:

```bash
go test -v antrea.io/antrea/test/e2e -provider=remote
```

You can specify ssh and kubeconfig locations with `-remote.sshconfig` and `-remote.kubeconfig`. The default location of `-remote.sshconfig` is `$HOME/.ssh/config` and the default location of `-remote.kubeconfig` is `$HOME/.kube/config`.

### Running the e2e tests on a Kind cluster

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
[document](../../docs/kind.md) for instructions on how to create a Kind cluster
and use Antrea as the CNI. You need at least one control-plane Node and one
worker Node. Before running the Go e2e tests, you will also need to copy the
Antrea manifest to the control-plane Docker container:

```bash
./hack/generate-manifest.sh | docker exec -i kind-control-plane dd of=/root/antrea.yml
go test -timeout=75m -v antrea.io/antrea/test/e2e -provider=kind
```

The default timeout of `go test` is [10 minutes](https://pkg.go.dev/cmd/go#hdr-Testing_flags).
If you encounter any timeout issue during e2e, you can try to increase timeout first. Some cases
take more than 10 minutes. eg: `go test -v -timeout=20m antrea.io/antrea/test/e2e -run=TestAntreaPolicy -provider=kind`.

`generate-manifest.sh` supports generating the Antrea manifest with different
Antrea configurations. Run `./hack/generate-manifest.sh --help` to see the
supported config options.

As part of code development, if you want to run the tests with local changes,
then make the code changes on the local repo and
[build the image](../../CONTRIBUTING.md#building-and-testing-your-change).
You can load the new image into the kind cluster using the command below:

```bash
kind load docker-image antrea/antrea-controller-ubuntu:latest antrea/antrea-agent-ubuntu:latest --name <kind_cluster_name>
```

By default, if a test case fails, we write some useful debug information to a
temporary directory on disk. This information includes the detailed description
(obtained with `kubectl describe`) and the logs (obtained with `kubectl logs`)
of each Antrea Pod at the time the test case exited. When running the tests in
verbose mode (i.e. with `-v`), the test logs will tell you the location of that
temporary directory. You may also choose your own directory using
`--logs-export-dir`. For example:

```bash
mkdir antrea-test-logs
go test -count=1 -v -run=TestDeletePod antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs
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
`go test -v antrea.io/antrea/test/e2e --prometheus`

## Running the performance test

To run all benchmarks, without the standard e2e tests:

```bash
go test -v -timeout=30m -run=XXX -bench=. \
    antrea.io/antrea/test/e2e \
    -perf.http.concurrency=16
```

The above command uses `-run=XXX` to deselect all `Test*` tests and uses `-bench=.` to select
all `Benchmark*` tests. Since performance tests take a while to complete, you need to extend
the timeout duration `-timeout` from the default `10m` to a longer one like `30m`.

If you would like to run the performance tests in a different scale, you could run:

```bash
go test -v -timeout=30m -run=XXX -bench=BenchmarkCustomize \
    antrea.io/antrea/test/e2e \
    -perf.http.requests=5000 \
    -perf.http.policy_rules=1000 \
    -perf.http.concurrency=16
```

All flags of performance tests includes:

* `performance.http.concurrency (int)`: Number of allowed concurrent http requests (default 1)
* `performance.http.requests (int)`: Total Number of http requests
* `performance.http.policy_rules (int)`: Number of CIDRs in the network policy
* `performance.realize.timeout (duration)`: Timeout of the realization of network policies (default 5m0s)
