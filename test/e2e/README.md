# Running the Antrea end-to-end tests

## Creating the test Kubernetes cluster

The tests must be run on an actual Kubernetes cluster. At the moment, we require
the cluster to be created using [Vagrant](https://www.vagrantup.com/) and the
provided [Vagrantfile](infra/vagrant/Vagrantfile), which you can do by following
the instructions below.

### Creating the test Kubernetes cluster with Vagrant

We use Vagrant to provision two Virtual Machines (one Kubernetes master node and
one worker node). The required software is installed on each machine with
[Ansible](https://www.ansible.com/). By default the Vagrantfile uses
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

Use the following Bash scripts to manage the Kubernetes nodes with Vagrant:

 * `./infra/vagrant/provision.sh`: create the required VMs and provision them
 * `./infra/vagrant/push_antrea.sh`: load the antrea/antrea-ubuntu Docker image
   to each node, along with the Antrea deployment YAML
 * `./infra/vagrant/suspend.sh`: suspend all node VMs
 * `./infra/vagrant/resume.sh`: resume all node VMs
 * `./infra/vagrant/destroy.sh`: destoy all node VMs, you will need to run
   `provision.sh` again to create a new cluster

Note that `./infra/vagrant/provision.sh` can take a while to complete but it
only needs to be run once.

#### Debugging

You can SSH into any of the node VMs using `vagrant ssh [node name]` (must be
run from the `infra/vagrant` directory. The master node is named
`k8s-node-master` and the worker nodes are named `k8s-node-worker-<N>` (for a
single worker node, the name is `k8s-node-worker-1`. `kubectl` is installed on
all the nodes.

## Running the tests

Make sure that your cluster was provisioned and that the Antrea build artifacts
were pushed to all the nodes. You can then run the tests from the top-level
directory with `go test -v github.com/vmware-tanzu/antrea/test/e2e` (the `-v` enables verbose output).

If you are running the test for the first time and are using the scripts we
provide under `infra/vagrant` to provision your Kubernetes cluster, you will
therefore need the following steps:

1. `./infra/vagrant/provision.sh`
2. `make`
3. `./infra/vagrant/push_antrea.sh`
4. `go test -v github.com/vmware-tanzu/antrea/test/e2e`

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

By default the description and logs for Antrea Pods are only written to disk if a
test fails. You can choose to dump this information unconditionally with
`--logs-export-on-success`.

## Tests to be added

 * Network policy tests
 * Reconciliation on start-up tests
