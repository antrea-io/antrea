# Antrea CI: Jenkins

## Reasons for Jenkins

We have tests as Github Actions but Jenkins allows tests running on a cluster of
multiple nodes and offers better environment setup options.

## Jenkins on cloud

At the moment these Jenkins jobs are running on VMC (VMware on AWS). As a
result, all jobs' results and details are available publicly
[here](https://jenkins.antrea-ci.rocks/). We are using Cluster API for vSphere
([CAPV](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere)) for
creating and managing workload clusters. The management cluster is a kind cluster
on Jenkins node. For each job build, a completely new workload cluster will be created
by this management cluster. As soon as the build finishes, the cluster
should be deleted. This ensures that all tests are run on a clean testbed.

## List of Jenkins jobs

[![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-eks-conformance-net-policy&subject=EKS%20Conformance/NetworkPolicy)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-eks-conformance-net-policy/) [![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-gke-conformance-net-policy&subject=GKE%20Conformance/NetworkPolicy%20)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-gke-conformance-net-policy/) [![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-aks-conformance-net-policy&subject=AKS%20Conformance/NetworkPolicy%20)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-aks-conformance-net-policy/)

* [e2e [gated check-in]](https://jenkins.antrea-ci.rocks/job/antrea-e2e-for-pull-request/):
  [end-to-end tests](/test/e2e) for Antrea.

* [conformance [gated check-in]](https://jenkins.antrea-ci.rocks/job/antrea-conformance-for-pull-request/):
  community tests using sonobuoy, focusing on "Conformance", and skipping "Slow",
  "Serial", "Disruptive", "Flaky", "Feature", "sig-cli",
  "sig-storage", "sig-auth", "sig-api-machinery", "sig-apps" and "sig-node".

* [network policy [gated check-in]](https://jenkins.antrea-ci.rocks/job/antrea-networkpolicy-for-pull-request/):
  community tests using sonobuoy, focusing on "Feature:NetworkPolicy".

* ipv6-ds-e2e: e2e tests in a dual-stack setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase e2e --registry ${DOCKER_REGISTRY}
```

* ipv6-ds-conformance: conformance tests in a dual-stack setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase conformance --registry ${DOCKER_REGISTRY}
```

* ipv6-ds-networkpolicy: NetworkPolicy tests in a dual-stack setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase networkpolicy --registry ${DOCKER_REGISTRY}
```

* ipv6-only-e2e: e2e tests in an IPv6 only setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase e2e --registry ${DOCKER_REGISTRY}
```

* ipv6-only-conformance: conformance tests in an IPv6 only setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase conformance --registry ${DOCKER_REGISTRY}
```

* ipv6-only-networkpolicy: NetworkPolicy tests in an IPv6 only setup.

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase networkpolicy --registry ${DOCKER_REGISTRY}
```

* windows e2e: e2e tests in a Windows setup.

```shell
#!/bin/bash
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase windows-e2e --registry ${DOCKER_REGISTRY}
```

* windows conformance: community tests on Windows cluster, focusing on "Conformance|sig-windows" and "sig-network",
  and skipping "LinuxOnly", "Slow", "Serial", "Disruptive", "Flaky", "Feature", "sig-cli", "sig-storage", "sig-auth",
  "sig-api-machinery", "sig-apps", "sig-node", "Privileged", "should be able to change the type from", "[sig-network]
  Services should be able to create a functioning NodePort service [Conformance]", "Service endpoints latency should not
  be very high".

```shell
#!/bin/bash
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase windows-conformance --registry ${DOCKER_REGISTRY}
```

* windows network policy: community tests on Windows cluster, focusing on "Feature:NetworkPolicy".

```shell
#!/bin/bash
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase windows-networkpolicy --registry ${DOCKER_REGISTRY}
```

* windows e2e with proxyAll enabled: e2e tests in a Windows setup with proxyAll enabled.

```shell
#!/bin/bash
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase windows-e2e --registry ${DOCKER_REGISTRY} --proxyall
```

* Multicast e2e: e2e tests in a multicast cluster

```shell
#!/bin/bash
set -e
DOCKER_REGISTRY="$(head -n1 ci/docker-registry)"
./ci/jenkins/test.sh --testcase multicast-e2e --registry ${DOCKER_REGISTRY}
```

* [whole-conformance [daily]](https://jenkins.antrea-ci.rocks/job/antrea-whole-conformance-for-pull-request/):
  community tests using sonobuoy, with certified-conformance mode.

* [daily-whole-conformance](https://jenkins.antrea-ci.rocks/job/antrea-daily-whole-conformance-for-period/):
  daily community tests using sonobuoy, with certified-conformance mode. If build fails, Jenkins will
  send an email to projectantrea-dev@googlegroups.com for notification.

* Microsoft Windows conformance: community tests related to Microsoft Windows.
  It focuses on: "[sig-network].+[Conformance]|[sig-windows]".
  It skips: "[LinuxOnly]|[Slow]|[Serial]|[Disruptive]|[Flaky]|[Feature:.+]|[sig-cli]|[sig-storage]|[sig-auth]|[sig-api-machinery]|[sig-apps]|[sig-node]|[Privileged]|should be able to change the type from|[sig-network] Services should be able to create a functioning NodePort service [Conformance]".

* Jenkins jobs validator [gated check-in]: this job only executes for PRs that include changes to
  [ci/jenkins/jobs](/ci/jenkins/jobs). It validates the syntax of the jenkins jobs'
  configuration.

* Jenkins Windows OVS validator: this job only executes for PRs that include changes to [hack/windows/Install-OVS.ps1](hack/windows/Install-OVS.ps1). It validates
  if Windows OVS can be installed correctly.

```shell
#!/bin/bash
./ci/jenkins/test.sh --testcase windows-install-ovs
```

* [EKS conformance/network policy [bi-daily]](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-eks-conformance-net-policy/)
  community tests on EKS cluster using sonobuoy, focusing on "Conformance" and "Feature:NetworkPolicy", skipping the same regexes as in job __conformance__ above, as well as "NodePort" (See [#690](https://github.com/antrea-io/antrea/issues/690)).\
  Current test environment matrix:

  |  K8s Version |    Node Type    |  Node AMI Family |  Status  |
  | :----------: | :-------------: | :--------------: | :------: |
  |     1.21     |  EC2 t3.medium  |   AmazonLinux2   |[![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-eks-conformance-net-policy)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-eks-conformance-net-policy/)|

* [GKE conformance/network policy [bi-daily]](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-gke-conformance-net-policy/)
  community tests on GKE cluster using sonobuoy, focusing on "Conformance" and "Feature:NetworkPolicy", skipping the same regexes as in job __conformance__ above.\
  Current test environment matrix:

  |  K8s Version   |     Node OS     | VPC Native Mode (on by default) |  Status  |
  | :------------: | :-------------: | :-----------------------------: |:-------: |
  |    1.21.6      |     Ubuntu      |  On                             |[![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-gke-conformance-net-policy)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-gke-conformance-net-policy/)|

* [AKS conformance/network policy [bi-daily]](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-aks-conformance-net-policy/)
  community tests on AKS cluster using sonobuoy, focusing on "Conformance" and "Feature:NetworkPolicy", skipping the same regexes as in job __conformance__ above.\
  Current test environment matrix:

  |  K8s Version   |  Node Type          |  Node OS        |  Status  |
  | :------------: | :-----------------: | :-------------: | :------: |
  |    1.21.7      |  Standard_DS2_v2    |  Ubuntu 18.04   |[![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=cloud-antrea-aks-conformance-net-policy)](http://jenkins.antrea-ci.rocks/view/cloud/job/cloud-antrea-aks-conformance-net-policy/)|

* [daily-elk-flow-collector-validate](https://jenkins.antrea-ci.rocks/job/antrea-daily-elk-flow-collector-validate-for-period/):
  [![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-daily-elk-flow-collector-validate-for-period)](http://jenkins.antrea-ci.rocks/view/cloud/job/antrea-daily-elk-flow-collector-validate-for-period/)
  daily validation of elk flow collector manifest. If build fails, Jenkins will send an email to
  projectantrea-dev@googlegroups.com for notification.

* [daily-flow-visibility-validate](https://jenkins.antrea-ci.rocks/job/antrea-daily-flow-visibility-validate-for-period/):
  [![Build Status](http://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-daily-flow-visibility-validate-for-period)](http://jenkins.antrea-ci.rocks/view/cloud/job/antrea-daily-flow-visibility-validate-for-period/)
  daily validation of Flow Visibility manifest. If build fails, Jenkins will send an email to
  projectantrea-dev@googlegroups.com for notification.

* [matrix-test [weekly]](https://jenkins.antrea-ci.rocks/job/antrea-weekly-matrix-compatibility-test/):
  runs Antrea e2e, K8s Conformance and NetworkPolicy tests, using different combinations of various operating systems and K8s releases.
  |  K8s Version   |  Node OS        |  Status  |
  | :------------: | :-------------: | :------: |
  |    1.17.5      |  CentOS 7       |[![Build Status](https://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-weekly-matrix-compatibility-test%2FIS_MATRIX_TEST%3DTrue%2CK8S_VERSION%3Dv1.17.5%2CTEST_OS%3Dcentos-7%2Clabels%3Dantrea-test-node)](https://jenkins.antrea-ci.rocks/job/antrea-weekly-matrix-compatibility-test/IS_MATRIX_TEST=True,K8S_VERSION=v1.17.5,TEST_OS=centos-7,labels=antrea-test-node/)|
  |    1.17.5      |  Photon 3.0     |[![Build Status](https://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-weekly-matrix-compatibility-test%2FIS_MATRIX_TEST%3DTrue%2CK8S_VERSION%3Dv1.17.5%2CTEST_OS%3Dphoton-3%2Clabels%3Dantrea-test-node)](https://jenkins.antrea-ci.rocks/job/antrea-weekly-matrix-compatibility-test/IS_MATRIX_TEST=True,K8S_VERSION=v1.17.5,TEST_OS=photon-3,labels=antrea-test-node/)|
  |    1.18.2      |  CentOS 7       |[![Build Status](https://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-weekly-matrix-compatibility-test%2FIS_MATRIX_TEST%3DTrue%2CK8S_VERSION%3Dv1.18.2%2CTEST_OS%3Dcentos-7%2Clabels%3Dantrea-test-node)](https://jenkins.antrea-ci.rocks/job/antrea-weekly-matrix-compatibility-test/IS_MATRIX_TEST=True,K8S_VERSION=v1.18.2,TEST_OS=centos-7,labels=antrea-test-node/)|
  |    1.18.2      |  Photon 3.0     |[![Build Status](https://jenkins.antrea-ci.rocks/buildStatus/icon?job=antrea-weekly-matrix-compatibility-test%2FIS_MATRIX_TEST%3DTrue%2CK8S_VERSION%3Dv1.18.2%2CTEST_OS%3Dphoton-3%2Clabels%3Dantrea-test-node)](https://jenkins.antrea-ci.rocks/job/antrea-weekly-matrix-compatibility-test/IS_MATRIX_TEST=True,K8S_VERSION=v1.18.2,TEST_OS=photon-3,labels=antrea-test-node/)|

If you need to run the K8s community tests locally, you may use the
[ci/run-k8s-e2e-tests.sh](/ci/run-k8s-e2e-tests.sh) script. It takes care of
installing the correct version of
[sonobuoy](https://github.com/vmware-tanzu/sonobuoy) and running the correct
subset of community tests for Antrea:

* To run conformance tests: `./run-k8s-e2e-tests.sh --e2e-conformance
  [--kubeconfig <Kubeconfig>]`.
* To run whole conformance tests: `./run-k8s-e2e-tests.sh --e2e-whole-conformance
  [--kubeconfig <Kubeconfig>]`.
* To run network policy tests: `./run-k8s-e2e-tests.sh --e2e-network-policy
  [--kubeconfig <Kubeconfig>]`.
* To run a single test by name: `./run-k8s-e2e-tests.sh --e2e-focus <TestRegex>
  [--kubeconfig <Kubeconfig>]`.

## Requirements

Yaml files under [ci/jenkins/jobs](/ci/jenkins/jobs) can be generated via
jenkins-job-builder. If you want to try out the tests on your local jenkins
setup, please notice the following requirements:

* Jenkins setup
  * Plugins: ghprb, throttle-concurrents
* Install
  [jenkins-job-builder](https://docs.openstack.org/infra/jenkins-job-builder/index.html)
* Define your `ANTREA_GIT_CREDENTIAL` which is the credential for your private
  repo
* Define your `ghpr_auth`, `antrea_admin_list`, `antrea_org_list` and
  `antrea_white_list` as
  [defaults](https://docs.openstack.org/infra/jenkins-job-builder/definition.html#defaults)
  variables in a separate file

### Apply the jobs

Run the command to test if jobs can be generated correctly.  

```bash
jenkins-jobs test -r ci/jenkins/jobs
```

Run the command to apply these jobs.  

```bash
jenkins-jobs update -r ci/jenkins/jobs
```

## Jenkins job updater

To follow GitOps best practices, there is a job-updater job in Jenkins to detect
any change in [ci/jenkins/jobs](/ci/jenkins/jobs) for every 15 min. As long as
a PR to modify code under that path is merged, Jenkins jobs on cloud should be
updated with new code.

## Tips for Developer

* [macro.yaml](/ci/jenkins/jobs/macros.yaml): Use "{{}}" instead of "{}" in "builder-list-tests" and "builder-conformance".
